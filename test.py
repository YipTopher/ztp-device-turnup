# Load device details from excel to dictionary query by batch ID
from pandas import concat, read_csv
devices_file_loc = './files/devices/Book1.csv'

def checkIfDuplicates(listOfElems):
    ''' Check if given list contains any duplicates '''   
    duplicates = [] 
    setOfElems = set()
    for elem in listOfElems:
        if elem in setOfElems:
            duplicates.append(elem)
        else:
            setOfElems.add(elem)         
    return duplicates

devices_csv = read_csv(devices_file_loc, keep_default_na=False, chunksize=10000)
devices_dict = concat((x.query("Batch == '{}'".format('Batch3')) for x in devices_csv), ignore_index=True).to_dict(orient='records')

# for device in devices_dict:
Host_Names = [d['Host_Name'] for d in devices_dict if 'Host_Name' in d]
Serial_Numbers = [d['Serial Number'] for d in devices_dict if 'Serial Number' in d]
print(Host_Names)
print(Serial_Numbers)

if checkIfDuplicates(Host_Names):
    print(checkIfDuplicates(Host_Names))
if checkIfDuplicates(Serial_Numbers):
    print(checkIfDuplicates(Serial_Numbers))

empty = []

for a in empty:
    print('nope')