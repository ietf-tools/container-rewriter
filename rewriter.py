#!/usr/bin/env python3
import threading
import logging
import Milter

import email.utils
import os
import re
import checkdmarc

logging.basicConfig(level=logging.INFO)


forwarding_addr = os.environ.get("FORWARDING_ADDR", "forwardingalgorithm@myaddr.com")
forwarding_domain = os.environ.get("FORWARDING_DOMAIN", "myaddr.com")
listening_port = os.environ.get("LISTENING_PORT", "8800")
mailmatch = re.compile(
    r"[-A-Za-z0-9!#$%&'*+/=?^_`{|}~]+(?:\.[-A-Za-z0-9!#$%&'*+/=?^_`{|}~]+)*=40(?:[A-Za-z0-9](?:[-A-Za-z0-9]*[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[-A-Za-z0-9]*[A-Za-z0-9])?",
    re.IGNORECASE,
)


def check_dmarc(email_addr):
    matches = ["reject", "quarantine"]
    domain = email_addr.split("@")[1]
    if any(x in checkdmarc.check_dmarc(domain)["tags"]["p"]["value"] for x in matches):
        return True
    else:
        return False


def check_wrapped(email_addr, domain):
    if email_addr.split("@")[-1] == domain:
        return True
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

            if self.mail_from and self.header_from:
                hdr_addr = email.utils.parseaddr(self.header_from)[1]
                if check_wrapped(self.mail_to, forwarding_domain):
                    logging.info(
                        f"[{self.id}] Unwrapped from {self.mail_to} to {unwrap_address(self.mail_to, forwarding_domain)}"
                    )
                    self.delrcpt(self.mail_to)
                    self.addrcpt(f"<{unwrap_address(self.mail_to, forwarding_domain)}>")
                    return Milter.ACCEPT
                else:
                    if check_dmarc(hdr_addr):
                        new_hdr_addr = (
                            f"{hdr_addr.replace('@', '=40')}@{forwarding_domain}"
                        )
                        self.chgfrom(forwarding_addr)
                        self.chgheader(
                            "From",
                            0,
                            new_hdr_addr,
                        )
                        logging.info(
                            f"[{self.id}] Envelope-From changed from {self.mail_from} to {forwarding_addr}"
                        )
                        logging.info(
                            f"[{self.id}] Header-From changed from {hdr_addr} to {new_hdr_addr}"
                        )
                    else:
                        logging.info(
                            f"[{self.id}] No change for Envelope-From {self.mail_from} or Header-From {hdr_addr}"
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
    main()
