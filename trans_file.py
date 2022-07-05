from os import walk,replace,path,mkdir
from zipfile import ZipFile
import re
from xml.dom.minidom import parseString
from ipaddress import ip_address , IPv4Network
from requests import get
from argparse import ArgumentParser
import PyPDF2

TOP_DIR = path.dirname(path.abspath(__file__))

def find_valid_urls():
    regex = r'('
    # Host and domain (including ccSLD):
    regex += r'(?:(?:[A-Z0-9][A-Z0-9-]{0,61}[A-Z0-9]\.)+)'
    # TLD:
    with open(path.join(TOP_DIR,'tlds','common_tlds.txt')) as tldtxt:
        tld_output = tldtxt.read()
    tld = '|'.join(tld_output.split('\n')[:-1])
    regex += fr'({tld})'
    # Port:
    regex += r'(?::(\d{1,5}))?'
    # Query path:
    regex += r'(?:(\/\S+)*)'
    regex += r'( |</w:t>|\n))'
    return re.compile(regex, re.IGNORECASE)


def make_block_list(new_file_name:str,fix_list:bool):
    get_urls = find_valid_urls()
    import_dir = 'digest_files'
    digest_loc = path.join(TOP_DIR,import_dir)
    _, _, filenames = next(walk(digest_loc))
    master_ip_list = []
    master_domain_list = []
    for file in filenames:
        if not file.endswith(('.docx','.pdf')):
            continue
        f_name = path.join(digest_loc,file)
        if file.endswith('.docx'):
            document = ZipFile(f_name)
            if 'word/document.xml' not in document.namelist():
                raise Exception('didn\'t find needed attr in file xml stuture please add this feature to fix')
            parsed_data = parseString(document.read('word/document.xml', pwd=None)).toprettyxml(indent=" ")
            # move processed files
            document.close()
        elif file.endswith('.pdf'):
            pdfFileObj = open(f_name, 'rb')
            pdfReader = PyPDF2.PdfFileReader(pdfFileObj)
            numpages = pdfReader.numPages
            parsed_data = ''
            for page in range(0,numpages):
                page_data = pdfReader.getPage(page)
                page_data = page_data.extractText().replace('\n \n',' ')
                page_data = page_data.replace('\n','')
                parsed_data +=  ' ' + page_data
            pdfFileObj.close()

        ip_4 = re.findall( r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2}|)', parsed_data)
        ip_6 = re.findall( r'\[?[A-F0-9]*:[A-F0-9:]+]?', parsed_data)
        ip_list_raw = ip_4 + ip_6
        for ip in ip_list_raw:
            try:
                # confirm whethers its a real IP and check if its a subnet or single
                if '/' not in ip:
                    takeip = f'{str(ip_address(ip))}/32'
                else:
                    try:
                        takeip = str(IPv4Network(ip))
                    except:
                        takeip = str(IPv4Network(ip.split('/')[0]))
                master_ip_list.append(takeip)
            except:
                continue
        url_list_raw = get_urls.findall(parsed_data)
        for url_tup in url_list_raw:
            if all(['schemas.microsoft.co' not in url_tup[0],'schemas.openxml'not in url_tup[0]]):
                data = re.sub('(</w:t>|/n)','',url_tup[0])
                master_domain_list.append(data)
        move_digest_to_spent_dir = path.join(TOP_DIR,'spent_files',file)
        if not path.exists(new_file_name):
            try:
                replace(f_name, move_digest_to_spent_dir)
            except Exception as e:
                print(e)
    
    if fix_list:
        master_ip_list = deduplicate_list(new_data=master_ip_list,data_type='ip')
        master_domain_list = deduplicate_list(new_data=master_domain_list,data_type='url')

    print(f'{len(master_ip_list)} IPs have been extracted')
    print(f'{len(master_domain_list)} URLs have been extracted')
    print('Please review before upload')
    print('combining and moving files....')
    master_ip_list = list(set(master_ip_list))
    master_domain_list = list(set(master_domain_list))

    output_path = path.join(TOP_DIR,'product')
    for type_,master in zip(['ip','url'],[master_ip_list,master_domain_list]):
        if len(master) == 0:
            continue
        write_file_name = path.join(output_path,type_,f'{new_file_name}_{type_}.txt')
        if not path.exists(write_file_name):
            with open(write_file_name,'w+') as nfn:
                for item in master:
                    nfn.write(f'{item}\n')
        else:
            raise FileExistsError(f'{write_file_name} already exist......')

def deduplicate_list(new_data:list,data_type:str,ignore_lines='#'):
    digest_loc = path.join(TOP_DIR,'misc_files')
    _, _, filenames = next(walk(digest_loc))
    master_list = []
    files_present = False
    for file in filenames:
        if not file.endswith('.txt'):
            continue
        elif data_type in file.lower():
            files_present = True
            f_name = path.join(digest_loc,file)
            with open(f_name,'r') as open_f:
                lines_list = open_f.readlines()
                dedup_list = list(set([line.rstrip() for line in lines_list]))
                master_list = list(set(master_list + dedup_list))
    if files_present:
        dedup_left = []
        master_list = [item for item in master_list if ignore_lines not in item]
        for nd in new_data:
            if nd not in master_list:
                dedup_left.append(nd)
        _, _, filenames = next(walk(digest_loc))
        for file in filenames:
            if not file.endswith('.txt'):
                continue
            elif data_type in file.lower():
                f_name = path.join(digest_loc,file)
                with open(f_name,'r+') as open_f:
                    lines_list = open_f.readlines()
                    master_list = [line.rstrip() for line in lines_list] + dedup_left
                with open(f_name,'w') as open_f:
                    open_f.truncate(0)
                    for m_item in master_list:
                        open_f.write(f'{m_item}\n')
                print(f'updated {f_name} with {len(dedup_left)} new items')
            return dedup_left
    else:
        return new_data

def term_trans():
    parser = ArgumentParser(prog='DoctorCandy')
    mandatory_args = parser.add_argument_group(title='DoctorCandy Mandatory Fields')
    mandatory_args.add_argument('-file_name', required=True, type=str,help='a unique output file name that will be appended to the file(s)')

    optional_args = parser.add_argument_group(title='DoctorCandy Optional Fields')
    optional_args.add_argument('--fix_list', default=False, type=bool,help='if you have a master list you want to compare to the current list')
    args = parser.parse_args()
    make_block_list(new_file_name=args.file_name,fix_list=args.fix_list)


if __name__ == "__main__":
    make_block_list(new_file_name='tester1801',fix_list=False)
    # term_trans()
