#!/usr/bin/env python3
import checkdmarc
import threading
import logging
from logging.handlers import TimedRotatingFileHandler

import Milter

import email.utils
import os
import re

from psycopg_pool import ConnectionPool
import psycopg

from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

forwarding_addr = os.environ.get("FORWARDING_ADDR", "forwardingalgorithm@myaddr.com")
forwarding_domain = os.environ.get("FORWARDING_DOMAIN", "myaddr.com")
local_domains = os.environ.get("LOCAL_DOMAINS", forwarding_domain)
rewrite_domains = os.environ.get("REWRITE_DOMAINS", "map[mydomain.com:dmarc.mydomain.com]")

rewrite_domain_map = {
    x.split(":")[0]: x.split(":")[1] for x in rewrite_domains[4:-1].split(" ")
}

milter_listening_port = os.environ.get("LISTENING_PORT", "8800")
http_listening_port = os.environ.get("HTTP_LISTENING_PORT", 8000)
log_level = os.environ.get("LOG_LEVEL", "INFO")
logging_procname = os.environ.get("LOGGING_PROCNAME", "milter/rewriter")
logging_filename = os.environ.get("LOGGING_FILENAME", "/var/log/rewrite.log")
logging_rotate_period = os.environ.get("LOGGING_ROTATE_PERIOD", "D")
logging_format = "{asctime} milter/rewriter[{process}]: {message} [{filename}:{lineno}]"

wrapped_regex = f"[-a-zA-Z0-9._%+]+=40[-a-zA-Z0-9.]+@{forwarding_domain}"
wrapped_mailmatch = re.compile(wrapped_regex, re.IGNORECASE)

listbounce_regex = "^[-_.0-9a-z]+-bounces+[-a-zA-Z0-9._%+]+=[-a-zA-Z0-9.]+"
listbounce_mailmatch = re.compile(listbounce_regex, re.IGNORECASE)

logging.basicConfig(
    level=log_level,
    style="{",
    datefmt="%b %d %H:%M:%S",
    format=logging_format
)

logger = logging.getLogger(__name__)
logger.setLevel(log_level)
file_handler = TimedRotatingFileHandler(
    logging_filename, when=logging_rotate_period, interval=1, backupCount=5
)

file_formatter = logging.Formatter(
    style="{",
    datefmt="%b %d %H:%M:%S",
    fmt=logging_format,
)

file_handler.setFormatter(file_formatter)

logger.addHandler(file_handler)
logging = logging.LoggerAdapter(logger)

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        if self.path != "/healthz":
            log_line = format % args
            logging.info(f"{log_line} [{self}]")

    def do_GET(self):
        if self.path == "/healthz":
            try:
                with get_db_pool() as pool:
                    with pool.connection() as connection:
                        with connection.cursor() as cur:
                            cur.execute("SELECT email from virtual LIMIT 1")
                            cur.fetchall()
                            self.send_response(200)
                            self.send_header("Content-type", "text/plain")
                            self.end_headers()
                            try:
                                self.wfile.write(b"OK")
                            except BrokenPipeError as e:
                                logging.debug(f"Client timeout: {e}")
            except psycopg.OperationalError:
                self.send_response(400)
                # Set the response headers
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                # Write the response content
                self.wfile.write(b"Not OK")
        else:
            self.send_response(400)
            # Set the response headers
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            # Write the response content
            self.wfile.write(b"Not OK")


def get_db_pool() -> ConnectionPool:
    try:
        pool = ConnectionPool(
            kwargs={
                "dbname": os.getenv("DB_NAME", "postfix"),
                "host": os.getenv("DB_HOST", "localhost"),
                "user": os.getenv("DB_USER", "postgres"),
                "password": os.getenv("DB_PASSWORD", "postgres"),
                "port": os.getenv("DB_PORT", "5432"),
            },
            check=ConnectionPool.check_connection,
        )
    except psycopg.OperationalError as e:
        logging.info(f"DB Error: {e}")
        raise e
    pool.open(wait=True)
    return pool


def test_virtual_alias(email_addr):
    with get_db_pool() as pool:
        with pool.connection() as connection:
            with connection.cursor() as cur:
                cur.execute("SELECT email from virtual where email = %s", (email_addr,))
                result = cur.fetchall()
    if len(result) > 0:
        return True
    else:
        return False


def check_dmarc(email_addr):
    matches = ["reject", "quarantine"]
    domain = email_addr.split("@")[1].replace(">", "")
    dmarc_status = checkdmarc.check_dmarc(domain)
    if "tags" in dmarc_status:
        if any(x in dmarc_status["tags"]["p"]["value"] for x in matches):
            return True
    else:
        return False


def check_spf(email_addr):
    matches = ["softfail", "fail"]
    domain = email_addr.split("@")[1]
    spf_status = checkdmarc.check_spf(domain)
    if "parsed" in spf_status:
        if any(x in spf_status["parsed"]["all"] for x in matches):
            return True
    else:
        return False

def check_local(email_addr):
    try:
        local_domain_list = local_domains.split(" ")
        domain = email_addr.split("@")[-1]
        return bool(len(set(local_domain_list).intersection(set(domain.split(" ")))))
    except AttributeError:
        return False

def update_addr_wrap_log(email_addr, new_email_addr):
    update_addr_wrap_log = f"""
    INSERT INTO virtual (email, destination, transport, source)
    VALUES ('{new_email_addr}', '{email_addr}', 'relay:', 'rewriter')
    ON CONFLICT (email) DO
    UPDATE SET updated = now();
    """
    try:
        with get_db_pool() as pool:
            with pool.connection() as connection:
                with connection.cursor() as cur:
                    cur.execute(update_addr_wrap_log)
    except psycopg.OperationalError as e:
        logging.info(f"failed to update addr_wrap_log: {e}")
    return True

class EnvelopeMilter(Milter.Base):
    def __init__(self):
        self.id = Milter.uniqueID()
        self.mail_from = None
        self.header_from = None

    def envfrom(self, f, *str):
        self.mail_from = f
        return Milter.CONTINUE

    def envrcpt(self, to, *str):
        self.mail_to = to
        return Milter.CONTINUE

    def header(self, name, value):
        if name.lower() == "from":
            self.header_from = value
        if name.lower() == "to":
            self.header_to = value
        return Milter.CONTINUE

    def eom(self):
        queue_id = self.getsymval('i') or ''  # authenticated user
        try:
            logging.debug(
                f"[{self.id}] Envelope-From: {self.mail_from}, Header-From: {self.header_from or 'N/A'}"
            )

            logging.debug(
                f"[{self.id}] Envelope-To: {self.mail_to or 'N/A'}, Header-To: {self.header_to or 'N/A'}"
            )

            hdr_from_name, hdr_from_addr = email.utils.parseaddr(self.header_from)
            env_from_addr = email.utils.parseaddr(self.mail_from)[1]
            hdr_to_addr = email.utils.parseaddr(self.header_to)
            env_to_addr = email.utils.parseaddr(self.mail_to)[1]

            # scenario 1
            if wrapped_mailmatch.match(env_to_addr):
                unwrapped_addr = env_to_addr.split("@")[0].replace("=40", "@")
                try:
                    with get_db_pool() as pool:
                        with pool.connection() as connection:
                            with connection.cursor() as cur:
                                cur.execute(f"""
                                            SELECT email FROM
                                            virtual WHERE email = '{env_to_addr}' and
                                            updated >= NOW() - INTERVAL '7 DAYS';
                                            """)
                                valid_unwraps = cur.fetchall()
                except (psycopg.OperationalError, psycopg.ProgrammingError) as e:
                    logging.info(f"{queue_id} unwrap: DB error validating {env_to_addr}, failing closed: {e} [{self.id}]")
                    return Milter.TEMPFAIL
                logging.debug(
                    f"debug: Header from: {hdr_from_addr} is remote, Header To: {hdr_to_addr} is wrapped local [{self.id}]"
                )
                logging.info(
                    f"{queue_id} unwrap: from {env_to_addr} to {unwrapped_addr} [{self.id}]"
                )
                if len(valid_unwraps) > 0:
                    self.delrcpt(env_to_addr)
                    self.addrcpt(f"<{unwrapped_addr}>")
                    return Milter.ACCEPT
                else:
                    logging.info(f"{queue_id} unwrap: failed to find valid unwrapping addr for {env_to_addr}")
                    return Milter.REJECT
            elif listbounce_mailmatch.match(env_to_addr):
                unwrapped_domain = [key for key, val in rewrite_domain_map.items() if val == env_to_addr.split('@')[1]][0]
                unwrapped_addr = env_to_addr.split("@")[1].replace(env_to_addr.split('@')[1], unwrapped_domain)
                logging.info(f"{queue_id} unwrap: list bounce unwrapped from {env_to_addr} to {unwrapped_addr}")

                self.delrcpt(env_to_addr)
                self.addrcpt(f"<{unwrapped_addr}>")
                return Milter.ACCEPT

            # scenario 2
            elif check_local(env_to_addr) and not test_virtual_alias(env_to_addr):
                logging.info(
                    f"{queue_id} none: Local list recipient, no action needed Envelope-To: {env_to_addr} Header-To: {hdr_to_addr} [{self.id}]"
                )
                return Milter.ACCEPT
            elif check_local(env_to_addr) and test_virtual_alias(env_to_addr):
                logging.debug(
                    f"{queue_id} debug: Virtual address recipient, check if rewrite needed Envelope-To: {env_to_addr} Header-To: {hdr_to_addr} [{self.id}]"
                )
                if check_dmarc(hdr_from_addr):
                    new_hdr_from_addr = (
                        f"{hdr_from_addr.replace('@', '=40')}@{forwarding_domain}"
                    )
                    update_addr_wrap_log(hdr_from_addr, new_hdr_from_addr)
                    forwarding_addr = os.environ.get("FORWARDING_ADDR", "forwardingalgorithm@myaddr.com")
                    self.chgfrom(forwarding_addr)
                    self.chgheader(
                        "From",
                        0,
                        new_hdr_from_addr,
                    )
                    logging.info(
                        f"{queue_id} rewrite-both: Envelope-From changed from {env_from_addr} to {forwarding_addr}, header-from changed {hdr_from_addr} to {new_hdr_from_addr} [{self.id}]"
                    )
                elif check_spf(hdr_from_addr):
                    logging.info(
                        f"{queue_id} rewrite-envelope: SPF only, Header-From: {hdr_from_addr} Envelope-From: {env_from_addr} [{self.id}]"
                    )
                    self.chgfrom(forwarding_addr)
                else:
                    logging.info(
                        f"{queue_id} none: No change for Envelope-From {env_from_addr} or Header-From {hdr_from_addr} [{self.id}]"
                    )
                return Milter.ACCEPT
            # scenario 3
            elif check_local(env_from_addr) and check_local(hdr_from_addr):
                logging.info(
                    f"{queue_id} none: List source, no action needed Envelope-From: {env_from_addr} Header-From: {hdr_from_addr} [{self.id}]"
                )
                return Milter.ACCEPT
            # no scenario match
            else:
                logging.debug(f"{queue_id} debug: Fall through [{self.id}]")
                rewrite_domain = rewrite_domain_map[env_from_addr.split("@")[1]]
                logging.info(f"rewrite domain is {rewrite_domain}")
                if check_dmarc(hdr_from_addr):
                    new_hdr_from_addr = (
                        f"{hdr_from_addr.replace('@', '=40')}@{forwarding_domain}"
                    )
                    self.chgheader(
                        "From",
                        0,
                        new_hdr_from_addr,
                    )
                    update_addr_wrap_log(hdr_from_addr, new_hdr_from_addr)
                    new_forwarding_addr = re.sub('@.*', '@' + rewrite_domain, env_from_addr)
                    self.chgfrom(new_forwarding_addr)
                    logging.info(
                        f"{queue_id} rewrite-both: Envelope-From changed from {env_from_addr} to {new_forwarding_addr} header-From changed from {hdr_from_addr} to {new_hdr_from_addr} [{self.id}]"
                    )
                elif check_spf(hdr_from_addr):
                    logging.info(
                        f"{queue_id} rewrite-envelope: SPF only, Header-From: {hdr_from_addr} Envelope-From: {env_from_addr} [{self.id}]"
                    )
                    new_forwarding_addr = re.sub('@.*', '@' + rewrite_domain, env_from_addr)
                    self.chgfrom(new_forwarding_addr)
                else:
                    logging.info(
                        f"{queue_id} none: No change for Envelope-From {env_from_addr} or Header-From {hdr_from_addr} [{self.id}]"
                    )
                return Milter.ACCEPT

        except Exception as e:
            logging.info(f"{queue_id} error: writing log: {e} [{self.id}]")
        return Milter.CONTINUE


def main():
    timeout = 600

    Milter.factory = EnvelopeMilter
    Milter.set_flags(Milter.ADDHDRS)

    def run_milter():
        Milter.runmilter("EnvelopeMilter", "inet:" + milter_listening_port, timeout)

    def run_http():
        server_address = ("", http_listening_port)
        # Create an instance of the threaded HTTP server
        httpd = ThreadingHTTPServer(server_address, SimpleHTTPRequestHandler)
        httpd.serve_forever()

    threads = []
    threads.append(threading.Thread(target=run_milter))
    threads.append(threading.Thread(target=run_http))
    for t in threads:
        t.start()
    for t in threads:
        t.join()


if __name__ == "__main__":
    logging.info(
        f"info: Starting, milter interface listneing on {milter_listening_port}"
    )
    logging.info(f"info: http interface listneing on {http_listening_port}")
    logging.info(f"info: Local domains are: {local_domains}")
    logging.info(f"info: logging rotation perdiod is {logging_rotate_period}")

    main()

