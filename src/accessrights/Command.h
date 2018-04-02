//
// Created by housa on 14-04-2017.
//

#ifndef PROJECT_COMMAND_H
#define PROJECT_COMMAND_H


#include <c++/string>
#include "Path.h"

class Command {

};

class ModifyAccessCommand : public Command {

private:
    std::string nodeid;

public:
    ModifyAccessCommand(std::string nodeid);
};

class OpCommand : public Command {

public:
    enum OP {
        insert, remove, modify
    };

private:
    OP op;
    Path path;

public:
    OpCommand(OP op, Path path);
};


#endif //PROJECT_COMMAND_H
