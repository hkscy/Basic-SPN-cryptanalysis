import basic_SPN

pbox = {0:0, 1:4, 2:8, 3:12, 4:1, 5:5, 6:9, 7:13, 8:2, 9:6, 10:10, 11:14, 12:3, 13:7, 14:11, 15:15}

#test pbox functionality
def testPBox(statem: list, pbox: dict):
    staten = [0]*len(pbox)
    for tpi, tp in enumerate(statem):
        staten[pbox[tpi]] = tp
    #print (staten)
    return staten  

testpBoxm = ['a','b','c','d', 'e','f','g','h', 'i','j','k','l', 'm','n','o','p']
testpBoxn = testPBox(testpBoxm, pbox)
testpBoxo = testPBox(testpBoxn, pbox)
if testpBoxm != testpBoxo: 
    print('FAIL: pbox inverse failed')
else:
    print('PASS: pbox inverse functional')
