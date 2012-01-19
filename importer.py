import numpy
import csv

reader = csv.reader(open("output_vectors.csv","rb"),delimiter=',')
x=list(reader)
result = numpy.array(x).astype('float')
X = result

print X.shape
print X.data
