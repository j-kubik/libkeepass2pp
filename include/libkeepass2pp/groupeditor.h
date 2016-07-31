#ifndef GROUPEDITOR_H
#define GROUPEDITOR_H

#include <QTabWidget>

namespace Ui {
class GroupEditor;
}

class GroupEditor : public QTabWidget
{
	Q_OBJECT

public:
	explicit GroupEditor(QWidget *parent = 0);
	~GroupEditor();

private:
	Ui::GroupEditor *ui;
};

#endif // GROUPEDITOR_H
