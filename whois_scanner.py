try:
    with open('.//files//whoischeck.txt') as check_file:
        data = check_file.read()
        check_list = data.strip().splitlines()
        for each in check_list:
            print(each + '\n')
except IOError as ierr:
    print('File opening error: ' + str(ierr))
