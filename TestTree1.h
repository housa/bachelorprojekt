//
// Created by housa on 14-04-2017.
//

#ifndef PROJECT_TESTTREE1_H
#define PROJECT_TESTTREE1_H

#include "Node.h"

Node* getTestTree1() {
    AccessRight* accessright = new AccessRight("housa", ModifyAccessCommand(".test"));
    Node* root = new Node({}, "html", accessright);

    Node* child1 = new Node({".test"}, "div", nullptr);

    std::vector<std::string> list = {"ul", "li"};
    AccessRight* accessright2 = new AccessRight("housa", OpCommand(OpCommand::insert, Path("todolist", Taglist(list))));
    Node* child2 = new Node({".todolist"}, "div", accessright2);

    root->addChild(child1);
    root->addChild(child2);

    return root;
}

#endif //PROJECT_TESTTREE1_H
