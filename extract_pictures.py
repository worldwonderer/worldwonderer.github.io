import re
import shutil

import requests

file_path = "_posts/2019-12-20-逆向某电商社区App.md"
image_path = "assets/images/20191220"


def download_pictures(urls):
    files = list()
    for n, url in enumerate(urls):
        r = requests.get(url, stream=True)
        path = image_path + '/' + '{}.jpg'.format(n)
        if r.status_code == 200:
            with open(path, 'wb') as f:
                r.raw.decode_content = True
                shutil.copyfileobj(r.raw, f)
                files.append(path)
    return files


def substitute_urls(urls, files):
    with open(file_path, 'r', encoding='utf8') as f:
        content = f.read()
        for i in range(len(urls)):
            content = content.replace(urls[i], '../' + files[i])
    print(content)


def extract_urls():
    with open(file_path, 'r', encoding='utf8') as f:
        urls = re.findall(r"\((https://app\.yinxiang\.com.*?)\)", f.read())
        return urls


def process():
    urls = extract_urls()
    files = download_pictures(urls)
    substitute_urls(urls, files)


if __name__ == '__main__':
    process()
