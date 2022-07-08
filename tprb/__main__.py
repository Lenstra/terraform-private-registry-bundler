import argparse
import os
import requests
import zipfile
import json
import base64
import logging
import urllib3
import hashlib

from dataclasses import dataclass


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig()


@dataclass
class Version:
    version: str
    key_id: str
    protocols: list[str]
    shasums_url: str
    shasums_signature_url: str
    filename: str

    def __post_init__(self):
        self.protocols = [
            "{:.1f}".format(int(p)) if '.' not in p else p
            for p in self.protocols
        ]


class TFEClient:
    def __init__(self, address, token):
        self._address = address
        self._token = token
        self.session = requests.Session()

    def request(self, method, path, json=None, data=None):
        return self.session.request(
            method,
            f'{self._address}/api/v2{path}',
            headers={
                'Authorization': f'Bearer {self._token}',
                'Content-Type': 'application/vnd.api+json'
            },
            json=json,
            data=data,
            verify=False
        )

    def check_error(self, response):
        try:
            response.raise_for_status()
        except requests.HTTPError:
            logging.exception('failed to validate response: %s', response.content)
            raise

    def get(self, path):
        response = self.request('GET', path)
        self.check_error(response)

        return response.json()

    def post(self, path, json=None, data=None):
        response = self.request('POST', path, json=json, data=data)
        self.check_error(response)

        return response.json()

    def delete(self, path):
        response = self.request('DELETE', path)
        self.check_error(response)

        return response.json()


commands = {}
def command(f):
    commands[f.__name__] = f


def get_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='version', version='0.1.0')
    subparsers = parser.add_subparsers(dest='command')

    bundle = subparsers.add_parser('bundle')
    bundle.add_argument('--namespace', required=True)
    bundle.add_argument('--type', required=True)
    bundle.add_argument('--os', required=True)
    bundle.add_argument('--arch', required=True)

    upload = subparsers.add_parser('upload')
    upload.add_argument('--tfe-address', required=True)
    upload.add_argument('--organization', required=True)
    upload.add_argument('--provider-name', required=True)
    upload.add_argument('--os', required=True)
    upload.add_argument('--arch', required=True)

    return parser


@command
def bundle(args):
    response = requests.get(f'https://registry.terraform.io/v1/providers/{args.namespace}/{args.type}/versions')
    response.raise_for_status()

    with zipfile.ZipFile('bundle.zip', 'w') as archive:

        versions = []
        for v in response.json()['versions']:
            response = requests.get(f'https://registry.terraform.io/v1/providers/{args.namespace}/{args.type}/{v["version"]}/download/{args.os}/{args.arch}')
            response.raise_for_status()

            package = response.json()

            filename = package['filename']
            response = requests.get(package['download_url'])
            response.raise_for_status()

            with archive.open(f'providers/{filename}', 'w') as f:
                f.write(response.content)

            response = requests.get(package['shasums_url'])
            response.raise_for_status()
            shasums_url = response.text

            response = requests.get(package['shasums_signature_url'])
            response.raise_for_status()
            shasums_signature_url = base64.b64encode(response.content).decode()

            versions.append(
                Version(
                    v['version'],
                    package['signing_keys']['gpg_public_keys'][0]['key_id'],
                    package['protocols'],
                    shasums_url,
                    shasums_signature_url,
                    filename
                )
            )

        data = json.dumps(versions).encode()

        with archive.open('versions.json', 'w') as f:
            f.write(data)


@command
def upload(args):
    token = os.environ['TFE_TOKEN']
    client = TFEClient(args.tfe_address, token)

    with zipfile.ZipFile('bundle.zip') as archive:
        with archive.open('versions.json') as f:
            versions = [
                Version(*e) for e in json.load(f)
            ]

        response = client.request(
            'GET',
            f"/organizations/{args.organization}/registry-providers/private/{args.organization}/{args.provider_name}",
        )
        if response.status_code == 404:
            client.post(
                f'/organizations/{args.organization}/registry-providers',
                {
                    "data": {
                        "type": "registry-providers",
                        "attributes": {
                            "name": args.provider_name,
                            "namespace": args.organization,
                            "registry-name": "private"
                        }
                    }
                }
            )

        else:
            response.raise_for_status()

        for v in versions:
            response = client.request(
                'DELETE',
                f'/organizations/{args.organization}/registry-providers/private/{args.organization}/{args.provider_name}/versions/{v.version}',
            )
            if response.status_code != 404:
                client.check_error(response)

            response = client.post(
                f'/organizations/{args.organization}/registry-providers/private/{args.organization}/{args.provider_name}/versions',
                json={
                    "data": {
                        "type": "registry-provider-versions",
                        "attributes": {
                            "version": v.version,
                            "key-id": v.key_id,
                            "protocols": v.protocols
                        }
                    }
                }
            )

            r = requests.put(
                response['data']['links']['shasums-upload'],
                data=v.shasums_url,
                verify=False
            )
            r.raise_for_status()

            r = requests.put(
                response['data']['links']['shasums-sig-upload'],
                data=v.shasums_signature_url,
                verify=False
            )
            r.raise_for_status()

            with archive.open(f'providers/{v.filename}') as f:
                data = f.read()

            response = client.post(
                f'/organizations/{args.organization}/registry-providers/private/{args.organization}/{args.provider_name}/versions/{v.version}/platforms',
                json={
                      "data": {
                        "type": "registry-provider-version-platforms",
                        "attributes": {
                            "os": args.os,
                            "arch": args.arch,
                            "shasum": hashlib.sha256(data).hexdigest(),
                            "filename": v.filename
                        }
                    }
                }
            )

            r = requests.put(
                response['data']['links']['provider-binary-upload'],
                data=data,
                verify=False
            )
            r.raise_for_status()


def main():
    parser = get_parser()
    args = parser.parse_args()

    command = commands[args.command]
    command(args)


if __name__ == '__main__':
    main()
