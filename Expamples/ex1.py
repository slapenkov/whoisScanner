##########################################################################
import asyncore as                                   _sys_asyncore
from asyncore import loop as                         _sys_asyncore_loop
import socket as                                     _sys_socket


##########################################################################
class _Whois_request(_sys_asyncore.dispatcher_with_send, object):
    # simple whois requester
    # original code by Frederik Lundh

    # -----------------------------------------------------------------------
    whoisPort = 43

    # -----------------------------------------------------------------------
    def __init__(self, consumer, host, provider):
        _sys_asyncore.dispatcher_with_send.__init__(self)
        self.consumer = consumer
        self.query = host
        self.create_socket(_sys_socket.AF_INET, _sys_socket.SOCK_STREAM)
        self.connect((provider, self.whoisPort,))

    # -----------------------------------------------------------------------
    def handle_connect(self):
        self.send(bytes('%s\r\n' % (self.query,), 'utf-8'))

    # -----------------------------------------------------------------------
    def handle_expt(self):
        self.close()  # connection failed, shutdown
        self.consumer.abort()

    # -----------------------------------------------------------------------
    def handle_read(self):
        # get data from server
        self.consumer.feed(self.recv(2048))

    # -----------------------------------------------------------------------
    def handle_close(self):
        self.close()
        self.consumer.close()


##########################################################################
class _Whois_consumer(object):
    # original code by Frederik Lundh

    # -----------------------------------------------------------------------
    def __init__(self, host, provider, result):
        self.texts_as_bytes = []
        self.host = host
        self.provider = provider
        self.result = result

    # -----------------------------------------------------------------------
    def feed(self, text):
        self.texts_as_bytes.append(text.strip())

    # -----------------------------------------------------------------------
    def abort(self):
        del self.texts_as_bytes[:]
        self.finalize()

    # -----------------------------------------------------------------------
    def close(self):
        self.finalize()

    # -----------------------------------------------------------------------
    def finalize(self):
        # join bytestrings and decode them (witha a guessed encoding):
        text_as_bytes = b'\n'.join(self.texts_as_bytes)
        self.result['text'] = text_as_bytes.decode('utf-8')


##########################################################################
class DRWHO:
    # -----------------------------------------------------------------------
    whois_providers = {
        '~isa': 'DRWHO/whois-providers',
        '*': 'whois.opensrs.net', }

    # -----------------------------------------------------------------------
    def whois(self, domain):
        R = {}
        provider = self._get_whois_provider('*')
        self._fetch_whois(provider, domain, R)
        return R

    # -----------------------------------------------------------------------
    def _get_whois_provider(self, top_level_domain):
        providers = self.whois_providers
        R = providers.get(top_level_domain, None)
        if R is None:
            R = providers['*']
        return R

    # -----------------------------------------------------------------------
    def _fetch_whois(self, provider, domain, pod):
        # .....................................................................
        consumer = _Whois_consumer(domain, provider, pod)
        request = _Whois_request(consumer, domain, provider)
        # .....................................................................
        _sys_asyncore_loop()  # loops until requests have been processed


# =========================================================================
DRWHO = DRWHO()

domain = 'google.com'
whois = DRWHO.whois(domain)
print(whois['text'])
