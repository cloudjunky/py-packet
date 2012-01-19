import numpy
import csv

from sklearn.cluster import KMeans
from numpy.random import RandomState

import pylab as pl

#Read in the array of values
reader = csv.reader(open("output_vectors.csv","rb"),delimiter=',')
x =list(reader)
X = numpy.array(x).astype('float')

print X.shape

rng = RandomState(42)

kmeans = KMeans(3, random_state=rng).fit(X)

print kmeans.cluster_centers_

print kmeans.labels_[-30:]
