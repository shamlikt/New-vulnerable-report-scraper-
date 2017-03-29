import xlwt
from copy import deepcopy
from requests import get
from bs4 import BeautifulSoup

class DataScraper:
    
    def __init__(self):
        ''' Initializing data structure, self.value is a python dict
       which is used for storing fields of excel table '''
        self.value ={'val_name': '--',
                    'severity' : '--',
                    'date' : '--',
                    'description': '--',
                    'affected': '--',
                    'solution': '--'
                    }
        self.data = []

    def get_html_data(self, url):
         ''' Method to fetch html data and return a Beutifulsoup object'''
         return BeautifulSoup(get(url).text, "html.parser")

    def scrape_kb_crt(self, url):
        ''' This method is used for parsing www.kb.cert.or'''
        data = self.get_html_data(url)
        lists = data.find(id="list-of-vuls").find_all("li") # Selecting list of valuns from https://www.kb.cert.org/vuls/
        for li in lists:
            temp_data = deepcopy(self.value)                # creating copy of self.value 
            temp_data['val_name'] = li.find("span", class_="vul-title truncate").text # parsing name using class name of span
            temp_data['date'] = li.find("span", class_="vul-date").text  # parsing published using class name of span 

            page_link = "{}{}".format(url.strip('/vuls/'),li.a['href'])   # Creating link address 
            new_data = self.get_html_data(page_link).find(id="vulnerability-note-content") # fetching link data and selecting a specific div using id 
            temp_data['description'] = new_data.p.text
            temp_data['solution'] = new_data.find_all("table")[2].find("tr").text # selecting solution part from html page using 'tr' tabs 
            self.data.append(temp_data) # appending temp data info to class variable called self.data


def write_data(file_name, data):
    ''' Method used for writing data into .xls file '''
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
