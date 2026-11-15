package engine

import "testing"

// js-nosqli-mongo-query leaves out a find() in a file importing typeorm (a
// repository on an SQL database binds its where), but not when the file also
// uses TypeORM's MongoDB side, the MongoDB driver, Mongoose or a collection,
// nor in a file without typeorm.
func TestUnlessImports(t *testing.T) {
	e := engineForTest(t)
	call := "app.get('/o', async (req, res) => {\n  res.json(await orderRepository.find({ where: { status: req.body.status } }));\n});\n"
	for _, c := range []struct {
		name, src string
		want      bool
	}{
		{"typeorm", "import { Repository, In } from 'typeorm';\n" + call, false},
		{"typeorm by require", "const { In } = require('typeorm');\n" + call, false},
		{"n8n's Db.collections", "import type { FindManyOptions } from 'typeorm';\napp.get('/e', async (req, res) => {\n  res.json(await Db.collections.Execution.find({ where: { id: req.query.id } }));\n});\n", false},
		{"no typeorm", call, true},
		{"typeorm and its MongoRepository", "import { MongoRepository } from 'typeorm';\n" + call, true},
		{"typeorm and mongoose", "import { In } from 'typeorm';\nimport mongoose from 'mongoose';\n" + call, true},
		{"typeorm and a collection", "import { In } from 'typeorm';\napp.get('/p', async (req, res) => {\n  res.json(await db.collection('p').find({ name: req.body.name }).toArray());\n});\n", true},
	} {
		fs, err := e.Scan("js", "a.ts", []byte(c.src))
		got := false
		for _, f := range fs {
			got = got || f.RuleID == "js-nosqli-mongo-query"
		}
		if err != nil || got != c.want {
			t.Errorf("%s: reported %v (err %v), want %v", c.name, got, err, c.want)
		}
	}
}
