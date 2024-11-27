import setuptools

setuptools.setup(
    name="oneaudit",
    version="1.5.3-dev",
    packages=setuptools.find_packages(),
    install_requires=[x.strip() for x in open("requirements.txt").readlines()],
    entry_points={
        'console_scripts': [
            'oneaudit = oneaudit.main:main',
        ],
    },
)