from os import walk,replace,path
from zipfile import ZipFile
import re
from xml.dom.minidom import parseString
from ipaddress import ip_address
from requests import get
from argparse import ArgumentParser


def find_valid_urls():
    regex = r'('
    # Host and domain (including ccSLD):
    regex += r'(?:(?:[A-Z0-9][A-Z0-9-]{0,61}[A-Z0-9]\.)+)'
    # TLD:
    try:
        tld = '|'.join(get('https://data.iana.org/TLD/tlds-alpha-by-domain.txt').text.split('\n')[1:])[:-1]
        regex += fr'({tld})'
    except Exception as e:
        print(e)
        regex += r'([A-Z]{2,6})'
    # Port:
    regex += r'(?::(\d{1,5}))?'
    # Query path:
    regex += r'(?:(\/\S+)*)'
    regex += r')'
    return re.compile(regex, re.IGNORECASE)


def make_block_list(new_file_name:str):
    get_urls = find_valid_urls()
    import_dir = 'digest_files'
    top_dir = path.dirname(path.abspath(__file__))
    digest_loc = f'{top_dir}/{import_dir}'
    _, _, filenames = next(walk(digest_loc))
    master_ip_list = []
    master_domain_list = []
    for file in filenames:
        if all([not file.endswith('.doc'), not file.endswith('.docx')]):
            continue
        f_name = f'{digest_loc}/{file}'
        document = ZipFile(f_name)
        if 'word/document.xml' not in document.namelist():
            raise Exception('didn\'t find needed attr in file xml stuture please add this feature to fix')
        parsed_xml = parseString(document.read('word/document.xml', pwd=None)).toprettyxml(indent=" ")
        ip_4 = re.findall( r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|', parsed_xml)
        ip_6 = re.findall( r'\[?[A-F0-9]*:[A-F0-9:]+]?', parsed_xml)
        ip_list_raw = ip_4 + ip_6
        for ip in ip_list_raw:
            try:
                master_ip_list.append(str(ip_address(ip)))
            except:
                continue
        url_list_raw = get_urls.findall(parsed_xml)
        for url_tup in url_list_raw:
            if all(['schemas.microsoft.co' not in url_tup[0],'schemas.openxml'not in url_tup[0]]):
                master_domain_list.append(url_tup[0])
        # move processed files
        move_digest_to_spent_dir = f"{top_dir}/spent_files/{file}"
        if not path.exists(new_file_name):
            try:
                replace(f_name, move_digest_to_spent_dir)
            except Exception as e:
                print(e)

    print(f'{len(master_ip_list)} IPs have been extracted')
    print(f'{len(master_domain_list)} URLs have been extracted')
    print('Please review before upload')
    print('combining and moving files....')
    master_ip_list = list(set(master_ip_list))
    master_domain_list = list(set(master_domain_list))

    output_path = f'{top_dir}/product'
    for type_,master in zip(['ip','url'],[master_ip_list,master_domain_list]):
        if len(master) == 0:
            continue
        write_file_name = f'{output_path}/{type_}/{new_file_name}_{type_}.txt'
        if not path.exists(write_file_name):
            with open(write_file_name,'w') as nfn:
                for item in master:
                    nfn.write(f'{item}\n')
        else:
            raise FileExistsError(f'{write_file_name} already exist......')


def term_trans():
    parser = ArgumentParser(prog='DoctorCandy')
    mandatory_args = parser.add_argument_group(title='DoctorCandy Mandatory Fields')
    mandatory_args.add_argument('-file_name', required=True, type=str,help='a unique output file name that will be appended to the file(s)')
    args = parser.parse_args()
    make_block_list(new_file_name=args.file_name)


if __name__ == "__main__":
    term_trans()