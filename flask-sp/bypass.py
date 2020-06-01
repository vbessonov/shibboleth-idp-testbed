import requests

if __name__ == '__main__':
    with open('assertion.xml') as file:
        assertion = file.read()

        requests.get('')