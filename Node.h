//
// Created by housa on 14-04-2017.
//

#ifndef PROJECT_NODE_H
#define PROJECT_NODE_H


#include <c++/vector>
#include <c++/string>
#include "accessrights/AccessRight.h"

class Node {

private:
    std::vector<std::string> classes;
    std::string tag;
    AccessRight* accessRight;

    Node* parent;
    std::vector<Node*> children;
public:
    Node(std::vector<std::string> classes, std::string tag, AccessRight* accessRight);
    ~Node();

    void setParent(Node* parent);
    void addChild(Node* child);
};


#endif //PROJECT_NODE_H
