import swaggerJSDoc from 'swagger-jsdoc'

const swaggerDefinition = {
  openapi: '3.0.0',
  info: {
    description: `<div><h4>Test Api</h4></div>`,
    title: 'Test Api',
    version: '1.0.0',
  },
  basePath: '/',
  tags: [
    {
      name: 'Users',
      description: 'Users endpoint',
    },
  ],
  components: {
    securitySchemes: {
      'x-api-key': {
        type: 'apiKey',
        name: 'x-api-key',
        in: 'header',
      },
    },
    security: {
      'x-api-key': [],
    },
  },
}
const options = {
  swaggerDefinition,
  apis: ['**/*.ts'],
}

const swaggerSpec = swaggerJSDoc(options)

export = swaggerSpec
