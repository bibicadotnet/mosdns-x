#!/usr/bin/env python3
import argparse
import datetime
import logging
import os
import subprocess
import zipfile

parser = argparse.ArgumentParser()
parser.add_argument("-i", type=int)
args = parser.parse_args()

PROJECT_NAME = 'mosdns'
RELEASE_DIR = './release'

logger = logging.getLogger(__name__)

# Target environments
envs = [
    [['GOOS', 'darwin'], ['GOARCH', 'amd64']],
    [['GOOS', 'darwin'], ['GOARCH', 'arm64']],
    [['GOOS', 'linux'], ['GOARCH', 'amd64']], # Forced to v3 by logic below
    [['GOOS', 'linux'], ['GOARCH', 'amd64'], ['GOAMD64', 'v3']],
    [['GOOS', 'linux'], ['GOARCH', 'amd64'], ['GOAMD64', 'v4']],
    [['GOOS', 'linux'], ['GOARCH', 'arm64']],
    [['GOOS', 'linux'], ['GOARCH', 'mipsle'], ['GOMIPS', 'softfloat']],
    [['GOOS', 'linux'], ['GOARCH', 'mips64le'], ['GOMIPS64', 'hardfloat']],
    [['GOOS', 'linux'], ['GOARCH', 'ppc64le']],
    [['GOOS', 'freebsd'], ['GOARCH', 'amd64']],
    [['GOOS', 'windows'], ['GOARCH', 'amd64']],
]

def go_build():
    logger.info(f'building {PROJECT_NAME}')

    global envs
    if args.i:
        envs = [envs[args.i]]

    VERSION = f'4.6.0'
    BuildTime = f'{datetime.datetime.now().strftime("%y.%m.%d")}'

    try:
        subprocess.check_call('go run ../ config gen config.yaml', shell=True, env=os.environ)
    except Exception:
        logger.exception('failed to generate config template')
        raise

    for env in envs:
        os_env = os.environ.copy()
        
        # Build-time optimization: Pure Go static binary
        os_env['CGO_ENABLED'] = '0'

        for pairs in env:
            os_env[pairs[0]] = pairs[1]

        # Force GOAMD64=v3 for all amd64 targets if not specified
        if os_env.get('GOARCH') == 'amd64' and 'GOAMD64' not in os_env:
            os_env['GOAMD64'] = 'v3'

        # Generate output name
        s = PROJECT_NAME
        for pairs in env:
            s = s + '-' + pairs[1]
        zip_filename = s + '.zip'
        
        suffix = '.exe' if os_env['GOOS'] == 'windows' else ''
        bin_filename = PROJECT_NAME + suffix

        # PIE is only meaningful on Linux
        buildmode = "-buildmode=pie" if os_env['GOOS'] == 'linux' else ""

        logger.info(f'building {zip_filename}')
        try:
            # FIX: Using ../default.pgo because we are inside RELEASE_DIR
            # Optimized flag order for compiler efficiency
            subprocess.check_call(
                f'go build {buildmode} '
                f'-pgo=../default.pgo '
                f'-trimpath '
                f'-ldflags "-s -w -buildid= '
                f'-X github.com/pmkol/mosdns-x/constant.Version={VERSION} '
                f'-X github.com/pmkol/mosdns-x/constant.BuildTime={BuildTime}" '
                f'-o {bin_filename} ../', 
                shell=True,
                env=os_env)

            with zipfile.ZipFile(zip_filename, mode='w', compression=zipfile.ZIP_DEFLATED, compresslevel=5) as zf:
                zf.write(bin_filename)
                zf.write('../README.md', 'README.md')
                zf.write('./config.yaml', 'config.yaml')
                zf.write('../LICENSE', 'LICENSE')

        except subprocess.CalledProcessError as e:
            logger.error(f'build {zip_filename} failed: {e.args}')

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    if not os.path.exists(RELEASE_DIR):
        os.mkdir(RELEASE_DIR)
    os.chdir(RELEASE_DIR)
    go_build()
