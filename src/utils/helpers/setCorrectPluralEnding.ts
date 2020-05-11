const setCorrectPluralEnding = (string: string) => {
  const ending =
    string.endsWith('ch') || string.endsWith('sh') || string.endsWith('x')
      ? 'es'
      : string.endsWith('s')
      ? 'ses'
      : string.endsWith('z')
      ? 'zes'
      : 's';

  return `${string}${ending}`;
};

export default setCorrectPluralEnding;
