#!/usr/bin/env python3
import threading
import logging
import Milter

import email.utils
import os
import re
import checkdmarc

from psycopg_pool import ConnectionPool
import psycopg

from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

forwarding_addr = os.environ.get("FORWARDING_ADDR", "forwardingalgorithm@myaddr.com")
forwarding_domain = os.environ.get("FORWARDING_DOMAIN", "myaddr.com")
local_domains = os.environ.get("LOCAL_DOMAINS", forwarding_domain)
milter_listening_port = os.environ.get("LISTENING_PORT", "8800")
http_listening_port = os.environ.get("HTTP_LISTENING_PORT", 8000)
log_level = os.environ.get("LOG_LEVEL", "DEBUG")
pool_cache: dict[ConnectionPool] = {}

mailmatch = re.compile(
    r"[-A-Za-z0-9!#$%&'*+/=?^_`{|}~]+(?:\.[-A-Za-z0-9!#$%&'*+/=?^_`{|}~]+)*=40(?:[A-Za-z0-9](?:[-A-Za-z0-9]*[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[-A-Za-z0-9]*[A-Za-z0-9])?",
    re.IGNORECASE,
)

logging.basicConfig(
    level=log_level,
    style="{",
    datefmt="%Y-%m-%d %H:%M:%S",
    format="{asctime} {levelname} {filename}:{lineno}: {message}",
)


class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
  def log_message(self, format, *args):
    if self.path != '/healthz':
      log_line = format % args
      logging.info(
        f"[{self}] {log_line}"
      )

  def do_GET(self):
    if self.path == '/healthz':
      try:
        with get_db_pool() as pool:
          with pool.connection() as connection:
            with connection.cursor() as cur:
              cur.execute("SELECT email from virtual LIMIT 1")
              cur.fetchall()
              self.send_response(200)
              self.send_header('Content-type', 'text/plain')
              self.end_headers()
              self.wfile.write(b"OK")
      except psycopg.OperationalError:
        self.send_response(400)
        # Set the response headers
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        # Write the response content
        self.wfile.write(b"Not OK")
    else:
      self.send_response(400)
      # Set the response headers
      self.send_header('Content-type', 'text/plain')
      self.end_headers()
      # Write the response content
      self.wfile.write(b"Not OK")


def get_db_pool() -> ConnectionPool:
  try:
    pool = ConnectionPool(kwargs={
      "dbname": os.getenv("DB_NAME", "postfix"),
      "host": os.getenv("DB_HOST", "localhost"),
      "user": os.getenv("DB_USER", "postgres"),
      "password": os.getenv("DB_PASSWORD", "postgres"),
      "port": os.getenv("DB_PORT", "5432")
    },check=ConnectionPool.check_connection)
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
    if len(result) == 1:
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


def check_wrapped(email_addr, domain):
    if email_addr.split("@")[-1] == domain:
        wrapped_addr = email_addr.split("@")[0]
        if mailmatch.match(wrapped_addr):
            unwrapped_addr = wrapped_addr.replace("=40", "@")
            return unwrapped_addr
    else:
        return False


def unwrap_address(email_addr, domain):
    if email_addr.split("@")[-1] == forwarding_domain:
        wrapped_addr = email_addr.split("@")[0]
        if mailmatch.match(wrapped_addr):
            unwrapped_addr = wrapped_addr.replace("=40", "@")
        else:
            unwrapped_addr = email_addr
    return unwrapped_addr


def check_local(email_addr):
    try:
        local_domain_list = local_domains.split(" ")
        domain = email_addr.split("@")[-1]
        return bool(len(set(local_domain_list).intersection(set(domain.split(" ")))))
    except AttributeError:
        return False


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
        try:
            logging.info(
                f"[{self.id}] Envelope-From: {self.mail_from}, Header-From: {self.header_from or 'N/A'}"
            )

            logging.info(
                f"[{self.id}] Envelope-To: {self.mail_to or 'N/A'}, Header-To: {self.header_to or 'N/A'}"
            )

            hdr_from_name, hdr_from_addr = email.utils.parseaddr(self.header_from)
            env_from_addr = email.utils.parseaddr(self.mail_from)[1]
            hdr_to_addr = email.utils.parseaddr(self.header_to)
            env_to_addr = email.utils.parseaddr(self.mail_to)[1]
            # scenario 1
            if unwrapped_addr := check_wrapped(env_to_addr, forwarding_domain):
                logging.info(
                    f"[{self.id}] Header from: {hdr_from_addr} is remote, Header To: {hdr_to_addr} is wrapped local"
                )
                logging.info(
                    f"[{self.id}] Unwrapped from {env_to_addr} to {unwrapped_addr}"
                )
                self.delrcpt(env_to_addr)
                self.addrcpt(f"<{unwrapped_addr}>")
                return Milter.ACCEPT
            # scenario 2
            elif check_local(env_to_addr) and not test_virtual_alias(env_to_addr):
                logging.info(
                    f"[{self.id}] Local list recipient, no action needed Envelope-To: {env_to_addr} Header-To: {hdr_to_addr}"
                )
                return Milter.ACCEPT
            elif check_local(env_to_addr) and test_virtual_alias(env_to_addr):
                logging.info(
                    f"[{self.id}] Virtual address recipient, check if rewrite needed Envelope-To: {env_to_addr} Header-To: {hdr_to_addr}"
                )
                if check_dmarc(hdr_from_addr):
                    new_hdr_from_addr = (
                        f"{hdr_from_addr.replace('@', '=40')}@{forwarding_domain}"
                    )
                    self.chgfrom(forwarding_addr)
                    self.chgheader(
                        "From",
                        0,
                        new_hdr_from_addr,
                    )
                    logging.info(
                        f"[{self.id}] Envelope-From changed from {env_from_addr} to {forwarding_addr}"
                    )
                    logging.info(
                        f"[{self.id}] Header-From changed from {hdr_from_addr} to {new_hdr_from_addr}"
                    )
                elif check_spf(hdr_from_addr):
                    logging.info(
                        f"[{self.id}] SPF only, Header-From: {hdr_from_addr} Envelope-From: {env_from_addr}"
                    )
                    self.chgfrom(forwarding_addr)
                else:
                    logging.info(
                        f"[{self.id}] No change for Envelope-From {env_from_addr} or Header-From {hdr_from_addr}"
                    )
                return Milter.ACCEPT
            # scenario 3
            elif check_local(env_from_addr) and check_local(hdr_from_addr):
                logging.info(
                    f"[{self.id}] List source, no action needed Envelope-From: {env_from_addr} Header-From: {hdr_from_addr}"
                )
                return Milter.ACCEPT
            # no scenario match
            else:
                logging.info(f"[{self.id}] Fall through")
                if check_dmarc(hdr_from_addr):
                    new_hdr_from_addr = (
                        f"{hdr_from_addr.replace('@', '=40')}@{forwarding_domain}"
                    )
                    self.chgfrom(forwarding_addr)
                    self.chgheader(
                        "From",
                        0,
                        new_hdr_from_addr,
                    )
                    logging.info(
                        f"[{self.id}] Envelope-From changed from {env_from_addr} to {forwarding_addr}"
                    )
                    logging.info(
                        f"[{self.id}] Header-From changed from {hdr_from_addr} to {new_hdr_from_addr}"
                    )
                elif check_spf(hdr_from_addr):
                    logging.info(
                        f"[{self.id}] SPF only, Header-From: {hdr_from_addr} Envelope-From: {env_from_addr}"
                    )
                    self.chgfrom(forwarding_addr)
                else:
                    logging.info(
                        f"[{self.id}] No change for Envelope-From {env_from_addr} or Header-From {hdr_from_addr}"
                    )
                return Milter.ACCEPT

        except Exception as e:
            logging.info(f"[{self.id}] ERROR writing log: {e}")
        return Milter.CONTINUE

def main():
    timeout = 600

    Milter.factory = EnvelopeMilter
    Milter.set_flags(Milter.ADDHDRS)

    def run_milter():
        Milter.runmilter("EnvelopeMilter", "inet:" + milter_listening_port, timeout)

    def run_http():
        server_address = ('', http_listening_port )
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
    logging.info(f"Starting, milter interface listneing on {milter_listening_port}")
    logging.info(f"http interface listneing on {http_listening_port }")
    logging.info(f"Local domains are: {local_domains}")

    main()
