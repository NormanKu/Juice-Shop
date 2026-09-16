export function login () {
  function afterLogin (user: User, res: Response, next: NextFunction) {
    verifyPostLoginChallenges(user)
    BasketModel.findOrCreate({ where: { UserId: user.id } })
      .then(([basket]: [BasketModel, boolean]) => {
        const authenticatedUser = { data: user, bid: basket.id }
        const token = security.authorize(authenticatedUser)
        security.authenticatedUsers.put(token, authenticatedUser)
        res.json({ authentication: { token, bid: basket.id, umail: user.email } })
      }).catch((error: Error) => {
        next(error)
      })
  }

  // Custom validator:
  // Only characters explicitly allowed in this email format can reach the SQL query.
  function getSafeEmail(input: unknown): string {
    if (typeof input !== 'string') {
      return ''
    }

    const allowedEmailPattern =
      /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/

    if (!allowedEmailPattern.test(input)) {
      return ''
    }

    return input
  }

  return (req: Request, res: Response, next: NextFunction) => {
    verifyPreLoginChallenges(req)

    const safeEmail = getSafeEmail(req.body.email)
    const hashedPassword = security.hash(req.body.password || '')

    models.sequelize.query(
      `SELECT * FROM Users
       WHERE email = '${safeEmail}'
       AND password = '${hashedPassword}'
       AND deletedAt IS NULL`,
      {
        model: UserModel,
        plain: true
      }
    )
      .then((authenticatedUser) => {
        const user = utils.queryResultToJson(authenticatedUser)

        if (user.data?.id && user.data.totpSecret !== '') {
          res.status(401).json({
            status: 'totp_token_required',
            data: {
              tmpToken: security.authorize({
                userId: user.data.id,
                type: 'password_valid_needs_second_factor_token'
              })
            }
          })
        } else if (user.data?.id) {
          afterLogin(user.data, res, next)
        } else {
          res.status(401).send(res.__('Invalid email or password.'))
        }
      }).catch((error: Error) => {
        next(error)
      })
  }
}
