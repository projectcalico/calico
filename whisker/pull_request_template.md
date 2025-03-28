## PR Checklist

### Why & What

- Why are you doing this and what have you added or changed?

### PR naming

- Your PR should be in the format: `[EU-XXXXX] Title of PR`

Note: branch names can use the following: `feature/` `task/` or `fix/` depending on issue type. E.g. `fix/EU-XXXXX`

### Ways of working

- [ ] Have you checked all ticket requirements have been met?
- [ ] Does your work conform to the project folder structure and file naming conventions?

### Component checklist

- [ ] Basic a11y support [WCAG 2.1](https://webaim.org/standards/wcag/checklist)
    - Use of semantic HTML
    - Should have logical flow of focus
    - Uses ARIA attributes where appropriate

### Testing checklist

- [ ] Added/updated unit tests
- [ ] Added/updated snapshot tests if appropriate
- [ ] Resolved any console errors in tests
- [ ] Manually tested against required browser support matrix
- [ ] Checked responsive styles for different devices
