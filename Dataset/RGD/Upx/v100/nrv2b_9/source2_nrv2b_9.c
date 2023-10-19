#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct _tree_node {
	struct _tree_node *left;
	struct _tree_node *right;
	int num;
} TreeNode;

int main()
{
	TreeNode *new1, *new2, *new3;
	TreeNode node1, node2, node3;

	new1    = (TreeNode *) malloc(sizeof(TreeNode));
	new1->num   = 70;
	new2    = (TreeNode *) malloc(sizeof(TreeNode));
	new2->num   = 50;

printf("new1 pointer is %p, new1 point value is %p\n", new1, new1->left);
	free(new1);
printf("new1 pointer is %p, new1 point value is %p\n", new1, new1->left);
	
printf("new2 pointer is %p, new2 point value is %p\n", new2, new2->left);
	free(new2);
printf("new2 pointer is %p, new2 point value is %p\n", new2, new2->left);

/*
	new3    = (TreeNode *) malloc(sizeof(TreeNode));
	printf("new3 pointer is %p, new3 left value is %p\n", new3, new3->left);
*/

	int a[10];
	printf("a[10] is %d\n", a[11]);
}