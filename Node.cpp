//
// Created by housa on 14-04-2017.
//

#include "Node.h"

Node::Node(std::vector<std::string> cs, std::string t, AccessRight* ar) {
    classes = cs;
    tag = t;
    accessRight = ar;
}

Node::~Node() {
    delete accessRight;
}

void Node::setParent(Node* parent) {
    this->parent = parent;
}

void Node::addChild(Node* child) {
    children.push_back(child);
    child->setParent(this);
}
