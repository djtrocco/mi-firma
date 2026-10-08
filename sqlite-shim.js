'use strict';
// Plan B para la base de datos: usa SQLite incorporado en Node (22.13 o más nuevo),
// sin compilar nada. Solo se usa si better-sqlite3 no se pudo instalar (típico en Windows).
const { DatabaseSync } = require('node:sqlite');
module.exports = class Database {
  constructor(file) { this.d = new DatabaseSync(file); }
  exec(sql) { return this.d.exec(sql); }
  prepare(sql) { return this.d.prepare(sql); }
  pragma(s) { this.d.exec('PRAGMA ' + s); }
};
