import argparse
import requests
import zipfile
import json
import base64

from collections import namedtuple


Version = namedtuple("Version", "version key_id protocols shasums_url shasums_signature_url filename")



def get_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='version', version='0.1.0')
    subparsers = parser.add_subparsers()

    bundle = subparsers.add_parser('bundle')
    bundle.add_argument('--namespace', required=True)
    bundle.add_argument('--type', required=True)
    bundle.add_argument('--os', required=True)
    bundle.add_argument('--arch', required=True)

    subparsers.add_parser('upload')

    return parser


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


def main():
    parser = get_parser()
    args = parser.parse_args()

    bundle(args)



if __name__ == '__main__':
    main()
