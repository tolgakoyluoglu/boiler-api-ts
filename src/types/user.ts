interface User {
  id: string
  username: string
  password: string
  sessions: string[]
  roles: string[]
  organisationId: string
}

export default User
