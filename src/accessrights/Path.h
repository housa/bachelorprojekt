//
// Created by housa on 14-04-2017.
//

#ifndef PROJECT_PATH_H
#define PROJECT_PATH_H


#include <c++/string>
#include "Taglist.h"

class Path {

private:
    std::string nodeid;
    Taglist taglist;

public:
    Path(std::string nodeid, Taglist
    taglist);
};


#endif //PROJECT_PATH_H
