from os import walk, replace, path, makedirs
from zipfile import ZipFile
import re
from xml.dom.minidom import parseString
from argparse import ArgumentParser
import pypdf


class TransferFiles:
    def __init__(self, output_name: str, fix_list: bool = False,fetch_new_tld: bool = False):
        self.master_domain_list = []
        self.master_ip_list = []
        self.output_name = output_name
        self.fix_list = fix_list
        self.fetch_new_tlds = fetch_new_tld
        self.top_dir = path.dirname(path.abspath(__file__))
        self.get_recent_tlds()

    def create_master_lists(self, list_type_: tuple, file_type_='pdf'):
        get_type = list_type_[0]
        obj_list = list_type_[1]

        # url_regex = r'\b(?:[a-zA-Z0-9-]+\.)+(?:' + self.tld_output + r')\b'
        url_regex = r'\b(?:[a-zA-Z0-9-]+\.)+(?:' + self.tld_output + r')\b'
        ip4_regex = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2}|)'
        ipv6_regex = r'\b((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|::(?:[0-9a-fA-F]{1,4}:){1,6}|[0-9a-fA-F]{1,4}::[0-9a-fA-F]{1,4})\b'

        if get_type == 'ip':
            if file_type_ == 'docx':
                ip_4 = re.findall(ip4_regex, obj_list)
                ip_6 = re.findall(ipv6_regex, obj_list)
                ip_list_raw = ip_4 + ip_6
            else:
                ip_4 = [re.findall(ip4_regex, get_ip4) for get_ip4 in obj_list]
                ip_6 = [re.findall(ipv6_regex, get_ip6) for get_ip6 in obj_list]
                ip_list_raw = ip_4 + ip_6
                # remove inner list, any specials , clean it up
                ip_list_raw = [ip_obj for sublist in ip_list_raw for ip_obj in sublist]
            self.master_ip_list += ip_list_raw

        elif get_type == 'url':
            if file_type_ == 'docx':
                # normalize string
                obj_list = obj_list.replace("[.]", ".")
                # get urls
                url_list_raw = re.findall(url_regex,obj_list,flags=re.IGNORECASE)
                fixed_url_list = []
                for url in url_list_raw:
                    if all(['schemas.microsoft.co' not in url, 'schemas.openxml' not in url]):
                        data = re.sub('(</w:t>|/n)', '', url)
                        fixed_url_list.append(data)
                cleaned_url = url_list_raw
            else:
                obj_list = ["".join(url.split()) for url in obj_list]
                # normalize list
                fixed_url = [url_obj.replace("[.]", ".") for url_obj in obj_list]
                # get URLs
                url_list_raw = [re.findall(url_regex,url_to_get,flags=re.IGNORECASE) for url_to_get in fixed_url]
                cleaned_url = [si for mi in url_list_raw for si in mi]

            self.master_domain_list += cleaned_url

    def block_creator_engine(self):
        digest_loc = self.top_dir
        _, _, filenames = next(walk(digest_loc))
        for file in filenames:
            file_type = None
            parsed_data = []

            if not file.endswith(('.docx', '.pdf')):
                continue

            f_name = path.join(digest_loc, file)
            if file.endswith('.docx'):
                file_type = 'docx'
                document = ZipFile(f_name)
                if 'word/document.xml' not in document.namelist():
                    raise Exception('didn\'t find needed attr in file xml stuture please add this feature to fix')
                parsed_data = parseString(document.read('word/document.xml', pwd=None))
                # with xml data pull only the body
                parsed_data = parsed_data.getElementsByTagName('w:body')[0].toprettyxml(indent=" ")

                document.close()
            elif file.endswith('.pdf'):
                file_type = 'pdf'
                pdfFileObj = open(f_name, 'rb')
                pdf_reader = pypdf.PdfReader(pdfFileObj)
                numpages = pdf_reader.get_num_pages()
                for page in range(0, numpages):
                    page_data = pdf_reader.get_page(page)
                    page_data = page_data.extract_text().split('\n')
                    page_data = [line.replace('\n', '') for line in page_data]
                    parsed_data = parsed_data + page_data
                pdfFileObj.close()

            ip_list_raw = ('ip', parsed_data)
            self.create_master_lists(file_type_=file_type, list_type_=ip_list_raw)

            url_list_raw = ('url', parsed_data)
            self.create_master_lists(file_type_=file_type, list_type_=url_list_raw)

            # need to move file so we dont have continually reopen our one file we are sending to product while being able to take in multple docs
            makedirs(path.join(self.top_dir, 'spent_files'), exist_ok=True)
            move_digest_to_spent_dir = path.join(self.top_dir, 'spent_files', file)
            if not path.exists(self.output_name):
                try:
                    replace(f_name, move_digest_to_spent_dir)
                except Exception as e:
                    print(e)

        if self.fix_list:
            self.master_ip_list = self.deduplicate_list(new_data=self.master_ip_list, data_type='ip')
            self.master_domain_list = self.deduplicate_list(new_data=self.master_domain_list, data_type='url')

    def make_block_list(self):
        self.block_creator_engine()

        master_ip_list = list(set(self.master_ip_list))
        master_domain_list = list(set(self.master_domain_list))
        print(f'{len(master_ip_list)} IPs have been extracted')
        print(f'{len(master_domain_list)} URLs have been extracted')
        print('combining and moving files....')

        # output_path = path.join(self.top_dir,'product')

        for type_, master in zip(['ip', 'url'], [master_ip_list, master_domain_list]):
            if len(master) == 0:
                continue
            # make the path if doesnt exist or use this path for the type_
            output_path = f'{self.top_dir}/product/{type_}'
            makedirs(output_path, exist_ok=True)

            while True:
                created = False
                write_file_name = path.join(output_path, f'{self.output_name}_{type_}.txt')
                if not path.exists(write_file_name):
                    with open(write_file_name, 'w+') as nfn:
                        for item in master:
                            nfn.write(f'{item}\n')
                    created = True
                else:
                    print(f'{write_file_name} already exist......')
                    self.output_name = input(f'please choose a new name: ')

                if created:
                    break

        print('Please review before upload')
        print('Files have been moved successfully :)')

    def deduplicate_list( self,new_data: list, data_type: str, ignore_lines='#'):
        digest_loc = path.join(self.top_dir, 'misc_files')
        _, _, filenames = next(walk(digest_loc))
        master_list = []
        files_present = False
        for file in filenames:
            if not file.endswith('.txt'):
                continue
            elif data_type in file.lower():
                files_present = True
                f_name = path.join(digest_loc, file)
                with open(f_name, 'r') as open_f:
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
                    f_name = path.join(digest_loc, file)
                    with open(f_name, 'r+') as open_f:
                        lines_list = open_f.readlines()
                        master_list = [line.rstrip() for line in lines_list] + dedup_left
                    with open(f_name, 'w') as open_f:
                        open_f.truncate(0)
                        for m_item in master_list:
                            open_f.write(f'{m_item}\n')
                    print(f'updated {f_name} with {len(dedup_left)} new items')
                return dedup_left
        else:
            return new_data

    def get_recent_tlds(self):
        # need to get common TLD else the parser will mix the tlds with a potential sentence end
        if self.fetch_new_tlds:
            # if we need a newer list
            from requests import get
            fetched_tld = get(f'https://data.iana.org/TLD/tlds-alpha-by-domain.txt')
            if fetched_tld.status_code == 200:
                with open(path.join(self.top_dir, 'tlds', 'common_tlds.txt'), 'w') as tldtxt:
                    tldtxt.write(fetched_tld.text)
        # pull tlds
        with open(path.join(self.top_dir, 'tlds', 'common_tlds.txt')) as tldtxt:
            tld_output = tldtxt.read()
            # make regex compatible
            tld_output = '|'.join(tld_output.split('\n')[1:])[:-1]
            self.tld_output = tld_output


def term_trans():
    parser = ArgumentParser(prog='DoctorCandy')
    mandatory_args = parser.add_argument_group(title='DoctorCandy Mandatory Fields')
    mandatory_args.add_argument('-output_name', required=True, type=str, help='a unique output file name that will be appended to the file(s)')

    optional_args = parser.add_argument_group(title='DoctorCandy Optional Fields')
    optional_args.add_argument('--fix_list', default=False, type=bool, help='if you have a master list you want to compare to the current list')

    optional_args = parser.add_argument_group(title='DoctorCandy Optional Fields')
    optional_args.add_argument('--fetch_new_tld', default=False, type=bool, help='if you to fetch a new TLD list from IANA')
    args = parser.parse_args()

    transf = TransferFiles(output_name=args.output_name, fix_list=args.fix_list, fetch_new_tld=args.fetch_new_tld)
    transf.make_block_list()


if __name__ == "__main__":
    tf = TransferFiles(output_name='tester_batch_1', fix_list=False, fetch_new_tld=False)
    # tf.make_block_list()
    term_trans()
