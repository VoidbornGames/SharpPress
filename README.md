# SharpPress

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![.NET](https://img.shields.io/badge/.NET-8.0-purple.svg)
![MySQL](https://img.shields.io/badge/MySQL-8.0-blue.svg)
![Architecture](https://img.shields.io/badge/Modular-100-red.svg)

A Modern Hybrid Headless CMS, highly modular content management system and web platform built with C# and .NET technologies. Designed with Modular architecture, extensible plugin support, and production-grade performance in mind, SharpPress provides developers with a flexible foundation for building everything from simple blogs and websites to complex enterprise web applications.

## Key Features

| Feature | Description |
|---------|-------------|
| **Plugin System** | Extensible plugin architecture for custom functionality |
| **C# Backend** | Built on modern .NET with ASP.NET Core |
| **Production Database** | MySQL support for enterprise-grade deployments |
| **Static File Serving** | Built-in caching for frequently accessed content |
| **Nginx Integration** | Ready for production deployment with reverse proxy configuration |

## Plugin Development
SharpPress's plugin architecture allows you to extend functionality without modifying core code. Check out the SamplePlugin.cs file for a template:

```C#
public class TestPlugin : IPlugin
{
    public string Name => "TestPlugin";
    public string Version => "2.1.155";
    public string Author=> "Alireza";
    public string? Description => "A simple test plugin";


    public async Task OnLoadAsync(IPluginContext context)
    {

    }

    public async Task OnUpdateAsync(IPluginContext context)
    {

    }

    public async Task OnUnloadAsync()
    {

    }
}
```

## Architecture
### Core Components

- API Layer: RESTful endpoints with JSON serialization
- Plugin Engine: Dynamic loading and dependency management
- Data Access: Entity Framework Core with MySQL provider
- Caching System: Intelligent caching for static and dynamic content
- Authentication/Authorization: Extensible security layer

## Database Schema
### Key Feature Details
- SharpPress uses a modular database design that expands with installed plugins.
- Automatically does the table creation and migration based on any C# model class.
- The class automatically maps C# objects to database rows (Object-Relational Mapping).

### Security & Stability: It includes protections against some common risks:
- **DeleteWhere** requires a **WHERE** clause to prevent accidental full-table deletion.
- **ExecuteQuery** restricts potentially destructive commands (**DROP**, **DELETE**, etc.), allowing only **SELECT** queries.
- It uses a **ConcurrentDictionary** to cache the reflected properties of model classes, improving the performance of frequent operations.

### Technical Notes
- Dependency: SharpPress relies on the MySqlConnector library for all database connectivity so you MUST have MySQL on your server.
- Id Convention: It requires model classes to inheritance from FeatherData class, which is mapped to a primary BIGINT AUTO_INCREMENT column.
- Connection Pooling: The connection string is configured with connection pooling enabled, which is good for web application performance.

## Security
**Please review our [Security Policy](SECURITY.md) for reporting vulnerabilities and security-related guidelines.**

## Code of Conduct
**We are committed to fostering an open and welcoming environment. Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before participating in our community.**

### Contributing
**We welcome contributions! Please read our Contributing Guidelines before submitting pull requests.**
1. Fork the repository
2. Create a feature branch (``` git checkout -b feature/amazing-feature ```)
3. Commit your changes (``` git commit -m 'Add amazing feature' ```)
4. Push to the branch (``` git push origin feature/amazing-feature ```)
5. Open a Pull Request

## License
### SharpPress is released under the MIT License. See the [LICENSE](LICENSE) file for details.


**Built for everyone by Alireza Janaki and contributors.**
