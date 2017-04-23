//
// Created by housa on 14-04-2017.
//

#ifndef PROJECT_TAGLIST_H
#define PROJECT_TAGLIST_H


#include <c++/vector>
#include <c++/string>

class Taglist {

private:
    std::vector<std::string> tags;
    Taglist* taglist;

public:
    Taglist(std::vector<std::string> tags, Taglist* taglist=nullptr);
};


#endif //PROJECT_TAGLIST_H
