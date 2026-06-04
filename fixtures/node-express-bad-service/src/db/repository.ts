export const db = {
  query(sql: string) {
    return Promise.resolve([{ sql }]);
  }
};

export const prisma = {
  order: {
    findMany(_args: object) {
      return Promise.resolve([]);
    }
  }
};

export function saveLoginAttempt(email: string) {
  return db.query("insert into login_attempts(email) values('" + email + "')");
}
