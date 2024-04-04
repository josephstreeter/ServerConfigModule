# Introduction 
This project is intended to create a PowerShell module for the configuration of new Windows Servers. 

# Getting Started
- Install the Plaster, Pester, and Documentarian modules
```
Install-Module -Name 'Plaster', 'Documentarian', 'Pester'
```
- Clone the Plaster Template
```
git clone https://github.com/Invoke-Automation/IAPlasterProjectTemplate/tree/master
rm -rf ./IAPlasterProjectTemplate/.git
mv ./IAPlasterProjectTemplate ./LocalTemplate
cp ./LocalTemplate ./<template location>
```
- Scaffold the module
```
$ModuleTemplatePath = Get-PlasterTemplate | Where-Object -FilterScript {$PSItem.Name -eq 'IAPlasterProjectTemplate'} | Select-Object -ExpandProperty TemplatePath

Invoke-Plaster -TemplatePath $ModuleTemplatePath -DestinationPath "./Module
```

# Build and Test
TODO: Describe and show how to build your code and run the tests. 

# Contribute
TODO: Explain how other users and developers can contribute to make your code better. 

If you want to learn more about creating good readme files then refer the following [guidelines](https://docs.microsoft.com/en-us/azure/devops/repos/git/create-a-readme?view=azure-devops). You can also seek inspiration from the below readme files:
- [ASP.NET Core](https://github.com/aspnet/Home)
- [Visual Studio Code](https://github.com/Microsoft/vscode)
- [Chakra Core](https://github.com/Microsoft/ChakraCore)