import argparse
import base64
import dataclasses
import hashlib
import json
import logging
import os
import requests
import sys
import urllib3
import zipfile
import zipimport

__version__ = '0.2.0'

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig()


@dataclasses.dataclass
class Version:
    name: str
    version: str
    key_id: str
    protocols: list[str]
    shasums: str
    shasums_signature: str
    filename: str
    os: str
    arch: str

    def __post_init__(self):
        self.protocols = [
            "{:.1f}".format(int(p)) if '.' not in p else p
            for p in self.protocols
        ]


class TFEClient:
    def __init__(self, address, token, session=None):
        self._address = address
        self._token = token

        if session is None:
            self._session = requests.Session()
        else:
            self._session = session

    def request(self, method, path, json=None, data=None):
        return self._session.request(
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
    parser.add_argument('--version', action='version', version=__version__)
    parser.add_argument('--verify', default=True, action=argparse.BooleanOptionalAction)

    subparsers = parser.add_subparsers(dest='command', required=True)

    bundle = subparsers.add_parser('bundle')
    bundle.add_argument('--provider', nargs='+', required=True)
    bundle.add_argument('--os', required=True)
    bundle.add_argument('--arch', required=True)

    upload = subparsers.add_parser('upload')
    upload.add_argument('--tfe-address', required=True)
    upload.add_argument('--organization', required=True)

    return parser


def _bundle_provider(session, archive, name, os, arch):
    response = session.get(f'https://registry.terraform.io/v1/providers/{name}/versions')
    response.raise_for_status()

    for v in response.json()['versions']:
        versions = []
        response = session.get(f'https://registry.terraform.io/v1/providers/{name}/{v["version"]}/download/{os}/{arch}')
        response.raise_for_status()

        package = response.json()

        filename = package['filename']
        response = session.get(package['download_url'])
        response.raise_for_status()

        with archive.open(f'providers/{name}/{v["version"]}/{filename}', 'w') as f:
            f.write(response.content)

        response = session.get(package['shasums_url'])
        response.raise_for_status()
        shasums = response.text

        response = session.get(package['shasums_signature_url'])
        response.raise_for_status()
        shasums_signature = base64.b64encode(response.content).decode()

        versions.append(
            Version(
                name,
                v['version'],
                package['signing_keys']['gpg_public_keys'][0]['key_id'],
                package['protocols'],
                shasums,
                shasums_signature,
                filename,
                os,
                arch,
            )
        )

    return versions


@command
def bundle(session, args):
    versions = []

    with zipfile.ZipFile('bundle.zip', 'w') as archive:
        for name in args.provider:
            response = session.get(f'https://registry.terraform.io/v1/providers/{name}/versions')
            response.raise_for_status()

            versions.extend(_bundle_provider(session, archive, name, args.os, args.arch))

        data = json.dumps([
            dataclasses.asdict(v) for v in versions
        ]).encode()

        with archive.open('versions.json', 'w') as f:
            f.write(data)

        # We store the version of tprb used to generate the archive so that we
        # can check when uploading it.
        with archive.open('VERSION', 'w') as f:
            f.write(__version__.encode())

        with archive.open('__main__.py', 'w') as f, \
            open(__file__, 'rb') as script:

            f.write(script.read())


@command
def upload(session, args):
    token = os.environ['TFE_TOKEN']
    client = TFEClient(args.tfe_address, token, session=session)

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

            r = session.put(
                response['data']['links']['shasums-upload'],
                data=v.shasums_url,
                verify=False
            )
            r.raise_for_status()

            r = session.put(
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

            r = session.put(
                response['data']['links']['provider-binary-upload'],
                data=data,
                verify=False
            )
            r.raise_for_status()


def main():
    if isinstance(__loader__, zipimport.zipimporter):
        sys.argv = ['tprb', 'upload'] + sys.argv[1:]

    parser = get_parser()
    args = parser.parse_args()

    session = requests.Session()
    session.verify = args.verify

    command = commands[args.command]
    command(session, args)


if __name__ == '__main__':
    main()
