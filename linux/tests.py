import x86AlphanumEncoder
import random

TESTS_COUNT = 1000

def getSubtractorsValidates(in_chunk, out_chunk):
    int_in_chunk = 0
    subtractors = list()
    print "[*] Subtractors: "

    for idx, digit in enumerate(reversed(in_chunk)):
        int_in_chunk += digit * (256 ** idx)

    for str_subtractor in out_chunk:
        int_subtractor = 0

        for idx, digit in enumerate(reversed(list(str_subtractor))):
            int_subtractor += ord(digit) * (256 ** idx)

        subtractors.append(int_subtractor)
        print hex(int_subtractor)

    curr_val = 0x00000000
    for s in subtractors:
        curr_val = (curr_val - s) % 0x100000000

    if curr_val != int_in_chunk:
        print "got:", hex(curr_val), "expected:", hex(int_in_chunk)


    return curr_val == int_in_chunk

def testGetSubtractors():
    pass_count = 0
    for idx in range(0, TESTS_COUNT):
        print "====================="
        test_chunk = [random.randint(0, 255) for x in range(0, 4)]
        # test_chunk = [116, 162, 110, 250]
        # print test_chunk
        subractors = x86AlphanumEncoder.getSubtractors(test_chunk)

        # print subractors

        if getSubtractorsValidates(test_chunk, subractors):
            print "[+] Test", idx, "out of", TESTS_COUNT, "PASSED"
            pass_count += 1
        else:
            print "[-] Test", idx, "out of", TESTS_COUNT, "FAILED"

    print "----------------------"
    print "[*] All tests complete -", str(float(pass_count) / float(TESTS_COUNT)), "pass rate"


def testGetByteDigit():
    tests = ((0xdeadbeef, 0, 0xef), (0xdeadbeef, 1, 0xbe), (0xdeadbeef, 2, 0xad), (0xdeadbeef, 3, 0xde))

    for t in tests:
        if t[2] == x86AlphanumEncoder.getByteDigit(t[0], t[1]):
            print "[+] getByteDigit test PASSED"
        else:
            print "[-] getByteDigit test FAILED"


if __name__ == "__main__":
    testGetByteDigit()
    testGetSubtractors()