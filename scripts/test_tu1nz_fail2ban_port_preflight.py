#!/usr/bin/env python3
import copy, importlib.util, pathlib, unittest
spec=importlib.util.spec_from_file_location("check",pathlib.Path(__file__).with_name("tu1nz_fail2ban_port_preflight.py"))
check=importlib.util.module_from_spec(spec);spec.loader.exec_module(check)

class StrictPortTests(unittest.TestCase):
    def setUp(self):
        self.before=[["set","sshd","ignoreip","100.64.0.0/10"],
          ["multi-set","sshd","action","nftables",[
          ["port","ssh"],
          ["actionstart","nft tcp dport { $(echo 'ssh' | sed s/:/-/g) } reject"],
          ["actionflush","flush; nft tcp dport { $(echo 'ssh' | sed s/:/-/g) } reject"],
          ["actionban","nft add element <ip>"]]],
          ["start","sshd"]]
        self.after=[["set","sshd","ignoreip","100.64.0.0/10"],
          ["multi-set","sshd","action","nftables",[
          ["port","2222"],
          ["actionstart","nft tcp dport { $(echo '2222' | sed s/:/-/g) } reject"],
          ["actionflush","flush; nft tcp dport { $(echo '2222' | sed s/:/-/g) } reject"],
          ["actionban","nft add element <ip>"]]],
          ["start","sshd"]]
    def test_exact_positive(self):
        before=copy.deepcopy(self.before)
        self.assertTrue(check.validate(self.before,self.after))
        self.assertEqual(self.before,before)
    def test_negative_cases(self):
        cases=[]
        for index,value in [(0,"22"),(0,"2222,22"),(1,"nft tcp dport 22 reject"),(2,"nft tcp dport 443 reject"),(3,"curl example.invalid")]:
            x=copy.deepcopy(self.after);x[1][4][index][1]=value;cases.append(x)
        x=copy.deepcopy(self.after);x[0][-1]="0.0.0.0/0";cases.append(x)
        x=copy.deepcopy(self.after);x.append(["start","unexpected"]);cases.append(x)
        x=copy.deepcopy(self.after);x[1][4].append(["port","2222"]);cases.append(x)
        x=copy.deepcopy(self.after);x[1][4][1][1]+="; touch /etc/unexpected";cases.append(x)
        x=copy.deepcopy(self.after);x.reverse();cases.append(x)
        cases.append(copy.deepcopy(self.before))
        for candidate in cases:
            with self.subTest(candidate=candidate):
                with self.assertRaises(ValueError):check.validate(self.before,candidate)
    def test_ambiguous_baseline(self):
        for original in [[],self.before+[self.before[1]], [["multi-set","sshd","action","nftables",[["port","22"]]]]]:
            with self.assertRaises(ValueError):check.validate(original,self.after)
if __name__=="__main__":unittest.main()
