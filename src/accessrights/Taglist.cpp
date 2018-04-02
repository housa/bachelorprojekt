//
// Created by housa on 14-04-2017.
//

#include "Taglist.h"

Taglist::Taglist(std::vector<std::string> tags, Taglist* taglist) {
    this->tags = tags;
    this->taglist = taglist;
}
