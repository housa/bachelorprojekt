//
// Created by housa on 14-04-2017.
//

#include "Command.h"

ModifyAccessCommand::ModifyAccessCommand(std::string id) {
    nodeid = id;
}

OpCommand::OpCommand(OpCommand::OP op, Path path) : path(path) {
    this->op = op;
}
