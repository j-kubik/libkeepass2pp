#include "groupeditor.h"
#include "ui_groupeditor.h"

GroupEditor::GroupEditor(QWidget *parent) :
	QTabWidget(parent),
	ui(new Ui::GroupEditor)
{
	ui->setupUi(this);
}

GroupEditor::~GroupEditor()
{
	delete ui;
}
