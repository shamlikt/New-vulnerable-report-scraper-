import xlwt
from copy import deepcopy
from requests import get
from bs4 import BeautifulSoup

class DataScraper:
    def __init__(self):
        self.value ={'val_name': '--',
                    'severity' : '--',
                    'date' : '--',
                    'description': '--',
                    'affected': '--',
                    'solution': '--'
                    }
        self.data = []

    def get_html_data(self, url):
         return BeautifulSoup(get(url).text, "html.parser")

    def scrape_kb_crt(self, url):
        data = self.get_html_data(url)
        lists = data.find(id="list-of-vuls").find_all("li")
        for li in lists:
            temp_data = deepcopy(self.value)
            temp_data['val_name'] = li.find("span", class_="vul-title truncate").text
            temp_data['date'] = li.find("span", class_="vul-date").text

            page_link = "{}{}".format(url.strip('/vuls/'),li.a['href'])
            new_data = self.get_html_data(page_link).find(id="vulnerability-note-content")
            temp_data['description'] = new_data.p.text
            temp_data['solution'] = new_data.find_all("table")[2].find("tr").text
            self.data.append(temp_data)


def write_data(file_name, data):
    book = xlwt.Workbook()
    sheet1 = book.add_sheet("sheet1")
    cols = ["A", "B", "C", "D", "E", "F"]
    heads = ['Vulnerability Name', 'Published Severity', 'Date of Release', 'Description', 'Product Affected', 'Solution',]

    row = sheet1.row(0)
    for index, value in enumerate(heads):
        row.write(index, value)

    number = 1
    for row_data in data:
        values = []
        row = sheet1.row(number)
        values.append(row_data['val_name'])
        values.append(row_data['severity'])
        values.append(row_data['date'])
        values.append(row_data['description'])
        values.append(row_data['affected'])
        values.append(row_data['solution'])

        for index, value in enumerate(values):
            row.write(index, value)
        number+=1
    book.save(file_name)
        

if __name__ == '__main__':
    obj= DataScraper()
    obj.scrape_kb_crt('https://www.kb.cert.org/vuls/')
    write_data('test1.xls', obj.data)
