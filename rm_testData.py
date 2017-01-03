#Remove any testdata/*.dat plaintext/ciphertext CSV files
import os

os.chdir('testData')
for r,d,files in os.walk('.'):
    for fileName in files[:len(files)-2]:
        print(fileName, end=', ')
        os.remove(fileName)
    if len(files) > 1:
        print(files[len(files)-2], end=' ') 
        os.remove(files[len(files)-2])
        print('& ', end='')
        print(files[len(files)-1], end='')
        os.remove(files[len(files)-1])
    elif len(files) == 1: 
        print(files[len(files)-1], end='')
        os.remove(files[len(files)-1])
    elif len(files) == 0:
        print('testData directory is empty.')
        exit()    
        
print(' removed.')  
print('{:} files removed.'.format(len(files)))      
