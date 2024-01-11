
import datetime
import time
from threading import Thread

import tls_client
import ua_generator
from eth_account.messages import encode_defunct
from web3 import Web3
from web3.auto import w3

from logger import MultiThreadLogger


class PVP_model:

    def __init__(self, private, proxy):

        self.proxy = proxy
        if proxy != None:
            proxy = proxy.split(':')
            proxy = f'http://{proxy[2]}:{proxy[3]}@{proxy[0]}:{proxy[1]}'

            self.proxy = {'http': proxy,
                          'https': proxy}

        self.private_key = private
        self.address = Web3(Web3.HTTPProvider('https://eth.llamarpc.com')).eth.account.from_key(self.private_key).address

        self.session = self._make_scraper()
        self.session.proxies = self.proxy
        self.ua = ua_generator.generate().text
        self.session.headers.update({"user-agent": self.ua})

    def Join(self):

        nonce = self.session.get("https://www.pvp.com/api/web3/nonce").text

        timestamp = str(datetime.datetime.now(datetime.timezone.utc).isoformat()).split("+")[0][:-3]+"Z"

        msg = f'www.pvp.com wants you to sign in with your Ethereum account:\n{self.address}\n\nSign in With Ethereum.\n\nURI: https://www.pvp.com\nVersion: 1\nChain ID: 137\nNonce: {nonce}\nIssued At: {timestamp}'
        message = encode_defunct(text=msg)

        signed_message = w3.eth.account.sign_message(message, private_key=self.private_key)

        signature = signed_message["signature"].hex()
        res = self.session.post("https://www.pvp.com/api/web3/validate-message",
                                json={"message":msg,
                                      "signature":signature}).json()

        try:
            if res['success'] == True:
                return True
            else:
                return False
        except:
            return False

    def _make_scraper(self):
        return tls_client.Session(client_identifier="chrome_120")


def split_list(lst, n):
    k, m = divmod(len(lst), n)
    return (lst[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n))

def distributor(list_, thread_number):

    logger = MultiThreadLogger(thread_number)

    for i in list_:

        model = PVP_model(private=i[1],
                          proxy=i[0])

        try:

            result = model.Join()

            if result:
                logger.success(f"{model.address} - Success")
            else:
                logger.error(f"{model.address} - Error")

            time.sleep(delay)
        except Exception as e:
            logger.error(f"{model.address} - Error ({str(e)})")

            time.sleep(delay)



if __name__ == '__main__':

    threads_count = 1
    delay = 0

    privates = []
    proxies = []

    with open('Files/Privates.txt', 'r') as file:
        for i in file:
            privates.append(i.rstrip())

    with open('Files/Proxy.txt', 'r') as file:
        for i in file:
            proxies.append(i.rstrip())

    while len(proxies) < len(privates):
        proxies.append(None)

    ready_array = []
    for index, item in enumerate(privates):
        ready_array.append([proxies[index], item])

    ready_array = split_list(ready_array, threads_count)

    print("Софт начал работу, прогресс выполнения можно смотреть в папке LogMT в соответствующих номерам потоков текстовиках")

    threads = []
    for index, i in enumerate(ready_array):
        thread = Thread(target=distributor,
                        args=(i,index))
        threads.append(thread)

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    input("Софт успешно прогнал вашу пачку")