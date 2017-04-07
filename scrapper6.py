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

    def scrape_vmware(self, url):
        data = self.get_html_data(url)
        section = data.find('div', class_ ="securityadvisorieslisting section")
        blocks = section.find_all("div", class_="news_block")[:10]  # only first 10 numbers

        for block in blocks:
            temp_data = deepcopy(self.value)
            temp_data['date'] = block.p.text
            temp_data['val_name'] = block.a.text.strip()
            link = block.a['href']
            domain_name = url.strip('/security/advisories')
            full_link = domain_name + link
            new_data = self.get_html_data(full_link)
            first_table = new_data.find("div", class_='comparisonTable section')
            table_rows = first_table.find_all('div', class_ = 'rTableRow')
            for row in table_rows:
                for span in row.find_all('span'):
                    span.decompose()
                raw_values = row.find_all('div', class_='rTableCell')
                if 'Severity' in raw_values[0].text:
                    temp_data['severity'] = raw_values[1].text
                elif 'Synopsis' in raw_values[0].text:
                    temp_data['description'] = raw_values[1].text

            paragraphs = new_data.find_all('div', class_="paragraphText parbase section")
            relevant_product_section = [ i for i in paragraphs if '2. Relevant Products' in i.text]
            if relevant_product_section:
                ul = relevant_product_section[0].find('ul')
                lis = ul.find_all('li')
                products = ''
                for li in lis:
                    br = li.find('br')
                    if br:
                        br.unwrap()
                    prod = li.text.strip()
                    products = '{}\n{}'.format(products, prod)
                temp_data['affected'] = products

            solution_section = [ i for i in paragraphs if '4. Solution' in i.text]
            if solution_section:                           # need to optimize solution parsing 
                text  = solution_section[0].text.strip()   
                text = text.replace('\xa0', '')
                temp_data['solution'] = text
            self.data.append(temp_data) # appending temp data info to class variable called self.data

    def scrape_microsoft(self, url):
        ''' This method is used for parsing https://technet.microsoft.com/en-us/security/advisories'''
        data = self.get_html_data(url)      # souping
        table_data = data.find('div', class_="", id="sec_advisory") # identifying the required tag
        for row in table_data.find_all('tr')[1:10]:   # Iterating through advisory column 
            temp_data = deepcopy(self.value)                # creating copy of self.value
            colomns = row.find_all('td')
            temp_data['date'] = colomns[0].text.strip()
            temp_data['val_name'] = colomns[2].text.strip()
            temp_data['severity'] = "Medium"
            page_link = colomns[2].find('a').get('href')    # child link to advisory
            new_data = self.get_html_data(page_link)    # souping

            temp_data['description'] = new_data.find("div", id="mainBody").find_all('p')[2].text    
            if new_data.find("table", summary="table"):     # checking for tables
                table = new_data.find("table", summary="table") # table datas
                table_rows = len(table.find_all('tr'))  # validating
                if(table_rows > 2):
                    affected_products = ''
                    for i in range(2,table_rows): # iterating for all affected products list
                        if(table.find_all('tr')[i].p):
                            product = table.find_all('tr')[i].p.text.strip()
                            affected_products = '{}\n{}'.format(affected_products, product)
                            temp_data['affected'] = affected_products # Only final value is getting written
                            
            temp_data['solution'] = "You will need to fix both direct dependencies and review and fix any transitive dependencies. "
            self.data.append(temp_data) # appending temp data info to class variable called self.data

    def scrape_fortinet(self, url):
        # ''' This method is used for parsing http://www.fortiguard.com/psirt'''
        data_fn = self.get_html_data(url)      # souping
        advisory_fn = data_fn.find('div', class_ ="results") # identifying the required tagset
        section_fn = advisory_fn.find_all('div', class_ ="title")
        for list in section_fn:
            temp_data_fn = deepcopy(self.value)
            temp_data_fn['val_name'] = list.text.strip()
            page_link_fn = "{}{}".format(url.strip('/psirt/'),list.a['href'])
            
            new_data_fn = self.get_html_data(page_link_fn)
            temp_data_fn['description'] = new_data_fn.find_all('div', class_="detail-item")[1].html.body.p.text.strip()
            
            new_table_fn = new_data_fn.find('table', class_="table table-responsive table-borderless")
            temp_data_fn['date'] = new_table_fn.find_all('tr')[1].find_all('td')[1].text.strip()
            temp_data_fn['severity'] = "Medium"
            temp_data_fn['affected'] = "Please find description"
            temp_data_fn['solution'] = "Information not available in website" 
            self.data.append(temp_data_fn) # appending temp data info to class variable called self.data

    def scrape_brocade(self, url):
        # ''' This method is used for parsing http://www.brocade.com/en/support/security-advisories.html'''
        data_br = self.get_html_data(url)      # souping

        table_br = data_br.find('table') # identifying the required tagset
        for row in table_br.find_all('tr')[1:20]:   # Iterating through advisory column 
            temp_data_br = deepcopy(self.value)
            temp_data_br['date'] = row.find_all('td')[3].text.strip()
            temp_data_br['val_name'] = row.find_all('td')[1].text.strip()
            page_link_br = "http://www.brocade.com"+(row.find_all('td')[0].a['href']) 
            
            new_data_br = self.get_html_data(page_link_br)
            temp_data_br['description'] = new_data_br.find_all('h1')[1].text.strip()
            
            new_table_br = new_data_br.find_all('table', class_="MsoTableGrid")[1]
            products_br = ''
            for new_row in new_table_br.find_all('tr')[1:]:   # Iterating through products affected column
                prod_br = new_row.find_all('td')[0].text.strip()
                products_br = '{}\n{}'.format(products_br, prod_br)
            temp_data_br['affected'] = products_br
            temp_data_br['solution'] = new_data_br.find_all('p', class_="MsoBodyText")[1].text.strip()

            new2_table_br = new_data_br.find_all('table', class_="MsoNormalTable")[0]
            for new_row in new2_table_br.find_all('p')[4]:   # Iterating through products affected column
                temp_data_br['severity'] = new_row.text.strip()
            self.data.append(temp_data_br) # appending temp data info to class variable called self.data
       
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
            row.write(index, value.strip())
        number+=1
    book.save(file_name)
        

def main():
    obj= DataScraper()
    obj.scrape_brocade('http://www.brocade.com/en/support/security-advisories.html')
    # obj.scrape_fortinet('http://www.fortiguard.com/psirt')
    # obj.scrape_microsoft('https://technet.microsoft.com/en-us/security/advisories')
    # obj.scrape_juniper('https://kb.juniper.net/InfoCenter/index?page=content&channel=SECURITY_ADVISORIES&cat=SIRT_1&sort=datemodified&&actp=&dir=descending&max=1000&batch=15&rss=true')
    # obj.scrape_kb_crt('https://www.kb.cert.org/vuls/')
    # obj.scrape_vmware('http://www.vmware.com/security/advisories')

    write_data('test.xls', obj.data)

if __name__ == '__main__':
    main()