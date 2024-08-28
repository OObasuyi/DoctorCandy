from os import walk, replace, path, makedirs
from zipfile import ZipFile
import re
from xml.dom.minidom import parseString
from argparse import ArgumentParser
import pypdf

TOP_DIR = path.dirname(path.abspath(__file__))


class TransferFiles():
    def __init__(self, output_name: str, fix_list: bool = False):
        self.master_domain_list = []
        self.master_ip_list = []
        self.output_name = output_name
        self.fix_list = fix_list

    @staticmethod
    def find_valid_urls():
        regex = r'\b(?:[a-zA-Z0-9-]+\[?\.\]?)+[a-zA-Z]{2,}\b'
        return re.compile(regex, re.IGNORECASE)

    def create_master_lists(self, list_type_: tuple, file_type_='pdf'):
        get_type = list_type_[0]
        obj_list = list_type_[1]
        if get_type == 'ip':
            if file_type_ == 'docx':
                ip_4 = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2}|)', obj_list)
                ip_6 = re.findall(r'\b((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|::(?:[0-9a-fA-F]{1,4}:){1,6}|[0-9a-fA-F]{1,4}::[0-9a-fA-F]{1,4})\b', obj_list)
                ip_list_raw = ip_4 + ip_6
            else:
                ip_4 = [re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2}|)', get_ip4) for get_ip4 in obj_list]
                ip_6 = [re.findall(r'\b((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|::(?:[0-9a-fA-F]{1,4}:){1,6}|[0-9a-fA-F]{1,4}::[0-9a-fA-F]{1,4})\b', get_ip6) for get_ip6 in obj_list]
                ip_list_raw = ip_4 + ip_6
                # remove inner list, any specials , clean it up
                ip_list_raw = [ip_obj for sublist in ip_list_raw for ip_obj in sublist]
            self.master_ip_list += ip_list_raw

        elif get_type == 'url':
            get_urls = self.find_valid_urls()
            if file_type_ == 'docx':
                url_list_raw = get_urls.findall(obj_list)
                fixed_url_list = []
                for url in url_list_raw:
                    if all(['schemas.microsoft.co' not in url, 'schemas.openxml' not in url]):
                        data = re.sub('(</w:t>|/n)', '', url)
                        fixed_url_list.append(data)
                fixed_url = [url.replace("[.]", ".") for url in fixed_url_list]
            else:
                obj_list = ["".join(url.split()) for url in obj_list]
                url_list_raw = [get_urls.findall(url_to_get) for url_to_get in obj_list]
                # remove inner list, any specials , clean it up
                fixed_url = [url_obj.replace("[.]", ".") for sublist in url_list_raw for url_obj in sublist]

            self.master_domain_list += fixed_url

    def block_creator_engine(self):
        digest_loc = TOP_DIR
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
            makedirs(path.join(TOP_DIR, 'spent_files'), exist_ok=True)
            move_digest_to_spent_dir = path.join(TOP_DIR, 'spent_files', file)
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

        print(f'{len(self.master_ip_list)} IPs have been extracted')
        print(f'{len(self.master_domain_list)} URLs have been extracted')
        print('combining and moving files....')
        master_ip_list = list(set(self.master_ip_list))
        master_domain_list = list(set(self.master_domain_list))

        # output_path = path.join(TOP_DIR,'product')

        for type_, master in zip(['ip', 'url'], [master_ip_list, master_domain_list]):
            if len(master) == 0:
                continue
            # make the path if doesnt exist or use this path for the type_
            output_path = f'{TOP_DIR}/product/{type_}'
            makedirs(output_path, exist_ok=True)

            write_file_name = path.join(output_path, f'{self.output_name}_{type_}.txt')
            if not path.exists(write_file_name):
                with open(write_file_name, 'w+') as nfn:
                    for item in master:
                        nfn.write(f'{item}\n')
            else:
                raise FileExistsError(f'{write_file_name} already exist......')

        print('Please review before upload')
        print('Files have been moved successfully :)')

    @staticmethod
    def deduplicate_list( new_data: list, data_type: str, ignore_lines='#'):
        digest_loc = path.join(TOP_DIR, 'misc_files')
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


def term_trans():
    parser = ArgumentParser(prog='DoctorCandy')
    mandatory_args = parser.add_argument_group(title='DoctorCandy Mandatory Fields')
    mandatory_args.add_argument('-output_name', required=True, type=str, help='a unique output file name that will be appended to the file(s)')

    optional_args = parser.add_argument_group(title='DoctorCandy Optional Fields')
    optional_args.add_argument('--fix_list', default=False, type=bool, help='if you have a master list you want to compare to the current list')
    args = parser.parse_args()

    transf = TransferFiles(output_name=args.output_name, fix_list=args.fix_list)
    transf.make_block_list()


if __name__ == "__main__":
    tf = TransferFiles(output_name='tester_batch_1', fix_list=False)
    tf.make_block_list()
    # term_trans()
