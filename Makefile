#
# Makefile
# Computer Networking Programing Assignments
#
#  Created by Phillip Romig on 4/3/12.
#  Copyright 2012 Colorado School of Mines. All rights reserved.
#

CXX = g++
LD = g++
CXXFLAGS = -g  -std=c++11 -DBOOST_LOG_DYN_LINK
LDFLAGS = -g 


#
# You should be able to add object files here without changing anything else
#
TARGET = packetstats
OBJ_FILES = main.o resultsC.o pk_processor.o statisticsC.o
INC_FILES = networkStructures.h	resultsC.h packetstats.h statisticsC.h


#
# Any libraries we might need.
#
LIBRARYS =  -lpcap  -lpthread -lboost_system -lboost_log_setup -lboost_log  -lboost_thread



${TARGET}: ${OBJ_FILES}
	${LD} ${LDFLAGS} ${OBJ_FILES} -o $@ ${LIBRARYS}

%.o : %.cc ${INC_FILES}
	${CXX} -c ${CXXFLAGS} -o $@ $<

#
# Please remember not to submit objects or binarys.
#
clean:
	rm -f core ${TARGET} ${OBJ_FILES}

#
# This might work to create the submission tarball in the formal I asked for.
#
submit:
	rm -f core ${TARGET} ${OBJ_FILES}
	mkdir `whoami`
	cp Makefile README.txt *.h *.cc `whoami`
	tar zcf `whoami`.tgz `whoami`
