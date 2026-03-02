#!/usr/bin/env python3
import threading
import logging
import Milter

import email.utils
import os
import re
import checkdmarc

forwarding_addr = os.environ.get("FORWARDING_ADDR", "forwardingalgorithm@myaddr.com")
forwarding_domain = os.environ.get("FORWARDING_DOMAIN", "myaddr.com")
local_domains = os.environ.get("LOCAL_DOMAINS", forwarding_domain)
listening_port = os.environ.get("LISTENING_PORT", "8800")
log_level = os.environ.get("LOG_LEVEL", "DEBUG")

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


def check_dmarc(email_addr):
    matches = ["reject", "quarantine"]
    domain = email_addr.split("@")[1].replace(">", "")
    dmarc_status = checkdmarc.check_dmarc(domain)
    if "tags" in dmarc_status:
        if any(x in dmarc_status["tags"]["p"]["value"] for x in matches):
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


def check_local(domain):
    try:
        local_domain_list = local_domains.split(" ")
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

            hdr_from_addr = email.utils.parseaddr(self.header_from)[1]
            env_from_addr = email.utils.parseaddr(self.mail_from)[1]
            hdr_to_addr = email.utils.parseaddr(self.header_to)[1]
            env_to_addr = email.utils.parseaddr(self.mail_to)[1]
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
            elif check_local(env_to_addr.split("@")[-1].replace(">", "")):
                logging.info(
                    f"[{self.id}] Local recipient, no action needed Envelope-From: {env_from_addr} Envelope-To: {env_to_addr}"
                )
                return Milter.ACCEPT
            elif check_local(hdr_from_addr.split("@")[-1].replace(">", "")):
                logging.info(
                    f"[{self.id}] Local source, no action needed Envelope-From: {env_from_addr} Envelope-To: {env_to_addr}"
                )
                return Milter.ACCEPT
            else:
                logging.info(
                    f"[{self.id}] Header-From is {hdr_from_addr} Header-To is {hdr_to_addr}"
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

    def run():
        Milter.runmilter("EnvelopeMilter", "inet:" + listening_port, timeout)

    t = threading.Thread(target=run)
    t.start()
    t.join()


if __name__ == "__main__":
    logging.info(f"Starting, listneing on {listening_port}")
    logging.info(f"Local domains are: {local_domains}")

    main()
