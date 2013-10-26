import sys
import re

def main():
	size = sys.argv[1]
	p = re.compile('(\d+\.?\d*)\s?([kmgt]?b)?',re.IGNORECASE)
	m = p.match(size)
	if not m:
		print 'Usage: python', __file__, '123mb'
		sys.exit(1)
	m = m.groups()
	n = float(m[0])
	if m[1]:
		m=m[1][0]
		if m.lower() == 'k':
			n *= 1e3
		if m.lower() == 'm':
			n *= 1e6
		if m.lower() == 'g':
			n *= 1e9
		if m.lower() == 't':
			n *= 1e12
	with open('test.file', 'w') as f:
		for i in range(0, int(n)):
			f.write('n')

if __name__ == '__main__':
	main()