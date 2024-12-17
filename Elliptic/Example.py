from EllipticCurve import *
import random
import re

p = 29
A, B = random.randint(0, p), random.randint(0,p)


E = EllipticCurve(p, A, B)
order = E.sea()
n = int(re.search(r'\d+', order).group())

print(f"E(a, b, p) = {A}, {B}, {p}, {n}")


