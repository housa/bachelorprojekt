//
// Created by housa on 14-04-2017.
//

#ifndef PROJECT_ACCESSRIGHT_H
#define PROJECT_ACCESSRIGHT_H


#include <c++/string>
#include "Command.h"

class AccessRight {

private:
    std::string userId;
    Command cmd;

public:
    AccessRight(std::string id, Command command);
};


#endif //PROJECT_ACCESSRIGHT_H
