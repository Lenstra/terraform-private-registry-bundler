#!/usr/bin/env python3

import argparse
import base64
import dataclasses
import hashlib
import json
import logging
import os
import zipfile
from collections import defaultdict

import requests
import urllib3

__version__ = "0.6.0"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclasses.dataclass
class Version:
    name: str
    version: str
    key_id: str
    protocols: list[str]
    shasums: str
    shasums_signature: str
    filename: str
    platform: str

    def __post_init__(self):
        self.protocols = [
            "{:.1f}".format(int(p)) if "." not in p else p for p in self.protocols
        ]


class TFESession(requests.Session):
    def __init__(self):
        super().__init__()

        self.tfe_hostname = os.environ.get("TFE_HOSTNAME", "app.terraform.io")

        self.headers = {
            "Content-Type": "application/vnd.api+json",
        }

        TFE_TOKEN = os.environ.get("TFE_TOKEN", "")
        if TFE_TOKEN:
            self.headers["Authorization"] = f"Bearer {TFE_TOKEN}"

    def request(self, method, url, *args, **kwargs):
        return super().request(
            method, f"https://{self.tfe_hostname}/{url}", *args, **kwargs
        )


commands = {}


def command(f):
    commands[f.__name__] = f


def get_provider_versions(provider_name, last_releases_only):
    response = requests.get(
        f"https://registry.terraform.io/v1/providers/{provider_name}/versions"
    )
    response.raise_for_status()
    return [version["version"] for version in response.json()["versions"]][
        -10 if last_releases_only else 0 :
    ]


def get_provider_package(provider_name, version, platform):
    response = requests.get(
        f"https://registry.terraform.io/v1/providers/{provider_name}/{version}/download/{platform}"
    )
    response.raise_for_status()

    package = response.json()

    response = requests.get(package["download_url"])

    response.raise_for_status()
    package["download"] = response.content

    response = requests.get(package["shasums_url"])
    response.raise_for_status()
    package["shasums"] = response.text

    response = requests.get(package["shasums_signature_url"])
    response.raise_for_status()
    package["shasums_signature"] = base64.b64encode(response.content).decode()

    return package


def bundle_provider(archive, provider_name, platform, last_releases_only):
    versions = get_provider_versions(provider_name, last_releases_only)

    bundle_gpg_keys = {}
    bundle_versions = []
    for version in versions:
        logging.info("Bundling %s v%s for %s", provider_name, version, platform)

        package = get_provider_package(provider_name, version, platform)
        with archive.open(
            f'providers/{provider_name}/{version}/{platform}/{package["filename"]}', "w"
        ) as f:
            f.write(package["download"])

        bundle_gpg_keys[
            package["signing_keys"]["gpg_public_keys"][0]["key_id"]
        ] = package["signing_keys"]["gpg_public_keys"][0]["ascii_armor"]

        bundle_versions.append(
            Version(
                provider_name,
                version,
                package["signing_keys"]["gpg_public_keys"][0]["key_id"],
                package["protocols"],
                package["shasums"],
                package["shasums_signature"],
                package["filename"],
                platform,
            )
        )

    return bundle_gpg_keys, bundle_versions


@command
def bundle(args):
    with zipfile.ZipFile("bundle.zip", "w") as archive:
        bundle_gpg_keys = {}
        bundle_versions = []
        for name in args.providers:
            for platform in args.platforms:
                i_bundle_gpg_keys, i_bundle_versions = bundle_provider(
                    archive, name, platform, args.last_releases_only
                )
                bundle_gpg_keys.update(i_bundle_gpg_keys)
                bundle_versions += i_bundle_versions

        with archive.open("gpg_keys.json", "w") as f:
            f.write(json.dumps(bundle_gpg_keys).encode())

        with archive.open("versions.json", "w") as f:
            f.write(
                json.dumps(
                    [
                        dataclasses.asdict(bundle_version)
                        for bundle_version in bundle_versions
                    ]
                ).encode()
            )

        # We store the version of tprb used to generate the archive so that we
        # can check when uploading it.
        with archive.open("VERSION", "w") as f:
            f.write(__version__.encode())


def create_provider(
    session, archive, organization, provider_namespace_name, provider_versions
):
    provider_namespace, provider_name = provider_namespace_name.split("/")

    for namespace in [organization, provider_namespace]:
        for registry_name in ["public", "private"]:
            response = session.delete(
                f"api/v2/organizations/{organization}/registry-providers/{registry_name}/{namespace}/{provider_name}",
            )
            if response.status_code != 404:
                response.raise_for_status()

    response = session.get(
        f"api/v2/organizations/{organization}/registry-providers/private/{organization}/{provider_name}",
    )
    if response.status_code == 404:
        response = session.post(
            f"api/v2/organizations/{organization}/registry-providers",
            json={
                "data": {
                    "type": "registry-providers",
                    "attributes": {
                        "name": provider_name,
                        "namespace": organization,
                        "registry-name": "private",
                    },
                }
            },
        )
        response.raise_for_status()

    else:
        response.raise_for_status()

    grouped_providers = defaultdict(list)
    for provider_version in provider_versions:
        grouped_providers[provider_version.version].append(provider_version)

    for provider_version in sorted(grouped_providers):
        bundle_versions = grouped_providers[provider_version]

        logging.info(
            "Uploading %s v%s",
            provider_name,
            provider_version,
        )

        response = session.delete(
            f"api/v2/organizations/{organization}/registry-providers/private/{organization}/{provider_name}/versions/{provider_version}",
        )
        if response.status_code != 404:
            response.raise_for_status()

        response = session.post(
            f"api/v2/organizations/{organization}/registry-providers/private/{organization}/{provider_name}/versions",
            json={
                "data": {
                    "type": "registry-provider-versions",
                    "attributes": {
                        "version": provider_version,
                        "key-id": bundle_versions[0].key_id,
                        "protocols": bundle_versions[0].protocols,
                    },
                }
            },
        )
        response.raise_for_status()

        create_data = response.json()

        response = session.put(
            create_data["data"]["links"]["shasums-upload"],
            data=bundle_versions[0].shasums,
        )
        response.raise_for_status()

        response = session.put(
            create_data["data"]["links"]["shasums-sig-upload"],
            data=base64.b64decode(bundle_versions[0].shasums_signature.encode()),
        )
        response.raise_for_status()

        for bundle_version in bundle_versions:
            with archive.open(
                f"providers/{provider_namespace}/{provider_name}/{bundle_version.version}/{bundle_version.platform}/{bundle_version.filename}"
            ) as f:
                provider_data = f.read()

            os, arch = bundle_version.platform.split("/")

            platform_create = response = session.post(
                f"api/v2/organizations/{organization}/registry-providers/private/{organization}/{provider_name}/versions/{bundle_version.version}/platforms",
                json={
                    "data": {
                        "type": "registry-provider-version-platforms",
                        "attributes": {
                            "os": os,
                            "arch": arch,
                            "shasum": hashlib.sha256(provider_data).hexdigest(),
                            "filename": bundle_version.filename,
                        },
                    }
                },
            )
            response.raise_for_status()

            response = session.put(
                platform_create.json()["data"]["links"]["provider-binary-upload"],
                data=provider_data,
            )
            response.raise_for_status()


def create_gpg_keys(session, archive, organization):
    with archive.open("gpg_keys.json") as f:
        gpg_keys = json.loads(f.read().decode())

    for key_id, ascii_armor in gpg_keys.items():
        response = session.get(
            f"api/registry/private/v2/gpg-keys/{organization}/{key_id}",
        )

        if response.status_code in (404, 500):
            response = session.post(
                "api/registry/private/v2/gpg-keys",
                json={
                    "data": {
                        "type": "gpg-keys",
                        "attributes": {
                            "namespace": organization,
                            "ascii-armor": ascii_armor,
                        },
                    }
                },
            )
            response.raise_for_status()

        else:
            response.raise_for_status()


@command
def upload(args):
    session = TFESession()
    session.verify = args.verify
    session.trust_env = args.verify

    with zipfile.ZipFile("bundle.zip") as archive:
        # Check that the bundle has the expected version
        with archive.open("VERSION") as f:
            version = f.read().decode()
            if version != __version__:
                raise ValueError(
                    f"Wrong bundle version, expected {__version__!r}, got {version!r}"
                )

        create_gpg_keys(session, archive, args.organization)

        with archive.open("versions.json") as f:
            bundle_versions = [Version(**e) for e in json.loads(f.read().decode())]

        providers = defaultdict(list)
        for bundle_version in bundle_versions:
            providers[bundle_version.name].append(bundle_version)

        for provider_name, provider_versions in providers.items():
            create_provider(
                session, archive, args.organization, provider_name, provider_versions
            )


def get_parser():
    parser = argparse.ArgumentParser()

    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--verify", default=True, action=argparse.BooleanOptionalAction)
    parser.add_argument(
        "--log-level", "-L", default="WARNING", choices=logging._nameToLevel.keys()
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    bundle = subparsers.add_parser("bundle")
    bundle.add_argument(
        "--providers",
        nargs="+",
        required=True,
        help="Providers as defined by Hashicorp: hashicorp/aws, microsoft/azuredevops...",
    )
    bundle.add_argument(
        "--platforms",
        nargs="+",
        required=True,
        help="Platforms as defined by Hashicorp: linux/amd64, windows/amd64...",
    )
    bundle.add_argument(
        "--last-releases-only",
        action="store_true",
        help="Download only the last releases (default to 10)",
    )

    upload = subparsers.add_parser("upload")
    upload.add_argument("--organization", required=True)

    return parser


def main():
    parser = get_parser()
    args = parser.parse_args()

    logging.basicConfig(level=args.log_level)

    command = commands[args.command]
    command(args)


if __name__ == "__main__":
    main()
